unit sp_reports;
{$mode objfpc}{$H+}
interface
uses SysUtils, fpjson, sp_common, sp_providers;
function RenderReply(const Service,Action,Arg:string; const R:TApiReply; Limit:Integer):string;
implementation
function Rows(J:TJSONData; const Keys:array of string):TJSONData;
var I:Integer; V:TJSONData;
begin
  if (J<>nil) and (J.JSONType=jtArray) then Exit(J);
  for I:=Low(Keys) to High(Keys) do begin
    V:=Field(J,Keys[I]); if (V<>nil) and (V.JSONType=jtArray) then Exit(V);
  end;
  raise ESafeError.Create('Provider schema changed: expected a known result array.');
end;
function Victims(J:TJSONData; const Service:string; Limit:Integer):string;
var A,O:TJSONData; I,N:Integer;
begin
  if Service='rlook' then A:=Rows(J,['posts']) else A:=Rows(J,['victims','data','results']);
  Result:='Ransomware listings / unverified claims'+#10;
  N:=A.Count; if N>Limit then N:=Limit;
  for I:=0 to N-1 do begin
    O:=A.Items[I];
    Result+=IntToStr(I+1)+'. '+Flat(FirstValue(O,['victim','post_title','name']),90)+#10+
      '   '+Flat(FirstValue(O,['group','group_name']),30)+' | '+Value(O,'country','--')+
      ' | observed '+Value(O,'discovered','unknown')+#10;
  end;
  Result+='Showing '+IntToStr(N)+' of '+IntToStr(A.Count)+' records returned. This is not independent confirmation.';
end;
function GroupList(J:TJSONData; Limit:Integer):string;
var A,O:TJSONData; I,N:Integer;
begin
  A:=Rows(J,['groups','data']); N:=A.Count; if N>Limit then N:=Limit;
  Result:='Tracked ransomware groups'+#10;
  for I:=0 to N-1 do begin
    O:=A.Items[I];
    if O.JSONType=jtString then Result+=IntToStr(I+1)+'. '+TextOf(O)+#10
    else Result+=IntToStr(I+1)+'. '+FirstValue(O,['group','name','group_name'])+
      ' | listed victims: '+Value(O,'victims','not supplied')+#10;
  end;
  Result+='Showing '+IntToStr(N)+' of '+IntToStr(A.Count)+'. Use group name:... for details.';
end;
function GroupDetail(J:TJSONData; const Arg:string):string;
begin
  if (J<>nil) and (J.JSONType=jtArray) then begin
    Require(J.Count>0,'No group details returned.'); J:=J.Items[0];
  end;
  Require((J<>nil) and (J.JSONType=jtObject),'Provider schema changed: expected a group object.');
  Result:='Group: '+Flat(Arg)+#10+
    'Listed victims: '+Value(J,'victims')+#10+
    'First seen: '+FirstValue(J,['firstseen','first_seen'])+#10+
    'Last seen: '+FirstValue(J,['lastseen','last_seen'])+#10;
  if Field(J,'description')<>nil then Result+=Flat(Field(J,'description').AsString,550)+#10;
  Result+='Threat-intelligence metadata only. No leak-site URLs, contact details or leaked content displayed.';
end;
function RenderReply(const Service,Action,Arg:string; const R:TApiReply; Limit:Integer):string;
var J,A,O,F:TJSONData; I,N:Integer;
begin
  J:=R.JSON; Result:='';
  if Service='ffraud' then begin
    Require((J<>nil) and (J.JSONType=jtObject),'Unexpected FFraud schema.');
    if SameText(Value(J,'success','true'),'false') then raise ESafeError.Create('FFraud could not complete this lookup.');
    if Action='ip' then begin
      Require(Field(J,'fraud_score')<>nil,'FFraud response lacks a reputation score.');
      Result:='IP reputation: '+Flat(Arg)+#10+
        'FFraud score: '+Value(J,'fraud_score')+'/100 | risk: '+Value(J,'risk')+#10+
        'VPN '+Value(J,'vpn')+' | proxy '+Value(J,'proxy')+' | Tor '+Value(J,'tor')+' | hosting '+Value(J,'hosting')+#10+
        'Known abuse '+Value(J,'is_abuser')+' | recent abuse '+Value(J,'recent_abuse')+#10+
        'Network: '+Value(J,'ASN')+' / '+Value(J,'organization')+#10+
        'Tags: '+ArrayText(Field(J,'threat_tags'),6)+#10+
        'Confidence: '+Value(J,'confidence')+#10;
      if Field(J,'reason')<>nil then Result+=Flat(Field(J,'reason').AsString,340)+#10;
      Result+='Signals, not proof of wrongdoing or a person''s identity.';
    end else Result:='Email reputation (address submitted to FFraud)'+#10+
      'Valid format: '+Value(J,'valid_format')+#10+
      'Disposable: '+Value(J,'is_disposable')+#10+
      'Role inbox: '+Value(J,'is_role_address')+#10+
      'Established domain: '+Value(J,'safe_domain')+#10+
      'Community blacklist: '+Value(J,'community_blacklisted')+#10+
      'Reports: '+Value(J,'blacklist_reports')+#10+
      'A reputation signal is not an identity verification.';
  end else if (Service='rlive') or (Service='rlook') then begin
    case Action of
      'recent','search':Result:=Victims(J,Service,Limit);
      'groups':Result:=GroupList(J,Limit);
      'group':Result:=GroupDetail(J,Arg);
      'stats':begin
        Require((J<>nil) and (J.JSONType=jtObject),'Unexpected RansomLook statistics schema.');
        Result:='RansomLook statistics'+#10+'Groups: '+Value(J,'groups')+#10+
          'Posts: '+Value(J,'posts_total')+#10+'Last 24h: '+Value(J,'posts_24h')+#10+
          'This month: '+Value(J,'posts_month')+#10+'Online group mirrors: '+Value(J,'groups_online');
      end;
    end;
  end else if Service='shodan' then begin
    Require((J<>nil) and (J.JSONType=jtObject),'Unexpected Shodan schema.');
    case Action of
      'host':Result:='Shodan indexed host: '+Flat(Arg)+#10+
        'Organization: '+Value(J,'org')+#10+'ASN: '+Value(J,'asn')+#10+
        'Ports: '+ArrayText(Field(J,'ports'),20)+#10+
        'Hostnames: '+ArrayText(Field(J,'hostnames'),5)+#10+
        'Vulnerability IDs (not verified here): '+ArrayText(Field(J,'vulns'),10)+#10+
        'Index updated: '+Value(J,'last_update')+#10+
        'Historical index data; no connection to this host was made.';
      'search':begin
        A:=Rows(J,['matches']); N:=A.Count; if N>Limit then N:=Limit;
        Result:='Shodan passive search | total: '+Value(J,'total')+#10;
        for I:=0 to N-1 do begin
          O:=A.Items[I]; Result+=Value(O,'ip_str')+':'+Value(O,'port')+' | '+Value(O,'org')+#10;
        end;
        Result+='Showing '+IntToStr(N)+' first-page indexed services; no active scan requested.';
      end;
      'count':begin
        Result:='Shodan matches: '+Value(J,'total')+#10;
        F:=Field(J,'facets'); A:=Field(F,'country');
        if (A<>nil) and (A.JSONType=jtArray) then
          for I:=0 to A.Count-1 do begin
            if I>=3 then Break;
            Result+=Value(A.Items[I],'value')+': '+Value(A.Items[I],'count')+#10;
          end;
      end;
      'dns':Result:='Shodan DNS: '+Flat(Arg)+#10+'Address: '+Value(J,LowerCase(Arg),'No address returned');
      'account':Result:='Shodan API account'+#10+'Plan: '+Value(J,'plan')+#10+
        'Query credits: '+Value(J,'query_credits')+#10+'Scan credits: '+Value(J,'scan_credits')+#10+
        'This bot never submits on-demand Shodan scans.';
    end;
  end;
  Require(Result<>'','No renderer for this provider operation.');
  Result+=#10+#10+ReplyMeta(R);
end;
end.
