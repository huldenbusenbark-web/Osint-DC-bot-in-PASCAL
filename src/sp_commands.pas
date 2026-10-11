unit sp_commands;
{$mode objfpc}{$H+}
interface
uses SysUtils, fpjson, sp_common;
type
  TCommandInput = record
    GroupName, Sub, Arg: string;
    Limit: Integer;
  end;
function CommandSchema: TJSONArray;
function ParseCommand(Data: TJSONData): TCommandInput;
function HelpText: string;
implementation
type
  TSpec=record G,S,Desc,Arg:string; HasLimit:Boolean; end;
const
  Specs:array[0..24] of TSpec=(
    (G:'help';S:'';Desc:'Command guide and data-handling notes';Arg:'';HasLimit:False),
    (G:'status';S:'';Desc:'Show configured capabilities without exposing keys';Arg:'';HasLimit:False),
    (G:'ffraud';S:'ip';Desc:'Passive public-IP reputation, proxy and VPN signals';Arg:'address';HasLimit:False),
    (G:'ffraud';S:'email';Desc:'Submit an authorized email address to FFraud for reputation checks';Arg:'address';HasLimit:False),
    (G:'rlive';S:'recent';Desc:'Recent ransomware victim claims, not independently verified';Arg:'';HasLimit:True),
    (G:'rlive';S:'search';Desc:'Search organization names in ransomware victim claims';Arg:'query';HasLimit:True),
    (G:'rlive';S:'groups';Desc:'List tracked ransomware groups';Arg:'';HasLimit:True),
    (G:'rlive';S:'group';Desc:'Ransomware group background and activity summary';Arg:'name';HasLimit:False),
    (G:'rlook';S:'recent';Desc:'Latest ransomware posts from RansomLook';Arg:'';HasLimit:True),
    (G:'rlook';S:'search';Desc:'Search organization claims; leak contents are never displayed';Arg:'query';HasLimit:True),
    (G:'rlook';S:'groups';Desc:'List tracked RansomLook groups';Arg:'';HasLimit:True),
    (G:'rlook';S:'group';Desc:'Group metadata without leak-site links or leaked files';Arg:'name';HasLimit:False),
    (G:'rlook';S:'stats';Desc:'RansomLook platform statistics';Arg:'';HasLimit:False),
    (G:'shodan';S:'host';Desc:'Passive indexed services and unverified vulnerability IDs';Arg:'address';HasLimit:False),
    (G:'shodan';S:'search';Desc:'Passive search; requires opt-in and may use query credits';Arg:'query';HasLimit:True),
    (G:'shodan';S:'count';Desc:'Count matches in the Shodan index';Arg:'query';HasLimit:False),
    (G:'shodan';S:'dns';Desc:'Resolve a domain through the Shodan API';Arg:'name';HasLimit:False),
    (G:'shodan';S:'account';Desc:'Plan and remaining credits (never API keys)';Arg:'';HasLimit:False),
    (G:'intel';S:'ip';Desc:'Combine FFraud and Shodan observations, preserving provenance';Arg:'address';HasLimit:False),
    (G:'intel';S:'org';Desc:'Compare organization claims across both ransomware trackers';Arg:'query';HasLimit:False),
    (G:'pentest';S:'scope';Desc:'Show this guild''s explicitly authorized test targets';Arg:'';HasLimit:False),
    (G:'pentest';S:'ports';Desc:'Connect-only check of up to eight configured TCP ports';Arg:'target';HasLimit:False),
    (G:'pentest';S:'headers';Desc:'One pinned HTTPS HEAD request; report security-header presence';Arg:'target';HasLimit:False),
    (G:'pentest';S:'tls';Desc:'Verify TLS hostname/chain and inspect leaf certificate metadata';Arg:'target';HasLimit:False),
    (G:'pentest';S:'dns';Desc:'Read A, AAAA and CAA via DoH for an authorized target';Arg:'target';HasLimit:False)
  );
function OptionsFor(const S:TSpec):TJSONArray;
var J:TJSONObject;
begin
  Result:=TJSONArray.Create;
  if S.Arg<>'' then begin
    J:=TJSONObject.Create(['type',3,'name',S.Arg,'description','Exact '+S.Arg+'; no URLs for addresses or target aliases',
      'required',True,'min_length',1,'max_length',254]);
    Result.Add(J);
  end;
  if S.HasLimit then Result.Add(TJSONObject.Create(['type',4,'name','limit','description','Results to display (default 5)',
    'required',False,'min_value',1,'max_value',10]));
end;
function CommandSchema:TJSONArray;
var I,J:Integer; Root,Sub:TJSONObject; Opt:TJSONArray;
begin
  Result:=TJSONArray.Create;
  for I:=Low(Specs) to High(Specs) do begin
    Root:=nil;
    for J:=0 to Result.Count-1 do if Value(Result.Items[J],'name','')=Specs[I].G then Root:=TJSONObject(Result.Items[J]);
    if Root=nil then begin
      Root:=TJSONObject.Create(['name',Specs[I].G,'type',1,'description','Sentinel: '+Specs[I].G,
        'default_member_permissions','0']);
      Result.Add(Root);
      if Specs[I].S<>'' then Root.Add('options',TJSONArray.Create);
    end;
    if Specs[I].S='' then Continue;
    Sub:=TJSONObject.Create(['type',1,'name',Specs[I].S,'description',Specs[I].Desc]);
    Opt:=OptionsFor(Specs[I]);
    if Opt.Count>0 then Sub.Add('options',Opt) else Opt.Free;
    TJSONArray(Root.Find('options')).Add(Sub);
  end;
end;
function ParseCommand(Data:TJSONData):TCommandInput;
var O,V,A:TJSONData; I,Index:Integer; Name,S:string; GotArg,GotLimit:Boolean;
begin
  Result:=Default(TCommandInput); Result.Limit:=5;
  Require((Data<>nil) and (Data.JSONType=jtObject),'Missing command data.');
  Result.GroupName:=Value(Data,'name',''); O:=Field(Data,'options');
  if not ((Result.GroupName='help') or (Result.GroupName='status')) then begin
    Require((O<>nil) and (O.JSONType=jtArray) and (O.Count=1),'Expected exactly one subcommand.');
    A:=O.Items[0]; Require(Value(A,'type','')='1','Invalid subcommand type.');
    Result.Sub:=Value(A,'name',''); O:=Field(A,'options');
  end;
  Index:=-1;
  for I:=Low(Specs) to High(Specs) do
    if (Specs[I].G=Result.GroupName) and (Specs[I].S=Result.Sub) then Index:=I;
  Require(Index>=0,'Unknown command. Use /help.');
  GotArg:=False; GotLimit:=False;
  if O<>nil then begin
    Require((O.JSONType=jtArray) and (O.Count<=2),'Invalid option list.');
    for I:=0 to O.Count-1 do begin
      A:=O.Items[I]; Name:=Value(A,'name',''); V:=Field(A,'value');
      Require(V<>nil,'Missing option value.');
      if (Name=Specs[Index].Arg) and (Name<>'') then begin
        Require((not GotArg) and (V.JSONType=jtString) and (Value(A,'type','')='3'),'Invalid string option.');
        S:=V.AsString;
        Require((Length(S)>0) and (Length(S)<=254),'Argument must be 1-254 bytes.');
        Require(S=Trim(S),'Remove leading/trailing whitespace from the argument.');
        Result.Arg:=S; GotArg:=True;
      end else if (Name='limit') and Specs[Index].HasLimit then begin
        Require((not GotLimit) and (V.JSONType=jtNumber) and (Value(A,'type','')='4'),'Invalid result limit.');
        Result.Limit:=StrToIntDef(V.AsString,0);
        Require((Result.Limit>=1) and (Result.Limit<=10),'Limit must be an integer from 1 to 10.'); GotLimit:=True;
      end else raise ESafeError.Create('Unknown or duplicate command option.');
    end;
  end;
  Require((Specs[Index].Arg='') or GotArg,'Missing required '+Specs[Index].Arg+' option.');
end;
function HelpText:string;
begin
  Result:='SENTINEL / Free Pascal' + #10+
    '/ffraud ip address:IP | email address:EMAIL'+#10+
    '/rlive recent | search query:ORG | groups | group name:GROUP'+#10+
    '/rlook recent | search query:ORG | groups | group name:GROUP | stats'+#10+
    '/shodan host address:IP | search query:QUERY | count query:QUERY'+#10+
    '/shodan dns name:DOMAIN | account'+#10+
    '/intel ip address:IP | org query:ORG'+#10+
    '/pentest scope | ports target:ALIAS | headers target:ALIAS'+#10+
    '/pentest tls target:ALIAS | dns target:ALIAS'+#10+
    '/help | /status'+#10+#10+
    'List/search commands accept limit:1..10 (default 5).'+#10+
    'All replies are ephemeral; authorized guild roles are required.'+#10+
    'Queries go to named providers. Only submit data you may share.'+#10+
    'Incident listings are claims; scores and CVEs are not proof.'+#10+
    'Pentest requires an extra role + exact, unexpired target scope.'+#10+
    'No shell execution, exploitation, downloads, or active Shodan scans.';
end;
end.
