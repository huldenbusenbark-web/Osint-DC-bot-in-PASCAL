unit sp_discord;
{$mode objfpc}{$H+}
interface
uses SysUtils, fpjson, sp_common, sp_config, sp_http;
procedure EditOriginal(C:TBotConfig; H:TTransport; const Token,Text:string);
procedure RegisterCommands(C:TBotConfig; H:TTransport);
implementation
uses sp_commands, sp_providers, Math;
procedure Deliver(H:TTransport; const Q:THttpRequest);
var R:THttpResponse; Attempt,MS:Integer; J,V:TJSONData; Wait:Double;
begin
  for Attempt:=0 to 2 do begin
    R:=H.Send(Q);
    if (R.Status>=200) and (R.Status<300) then Exit;
    if (R.Status=429) and (Attempt<2) then begin
      Wait:=StrToFloatDef(HeaderValue(R.Headers,'Retry-After'),1,DefaultFormatSettings);
      try
        J:=ParseJSONSafe(R.Body);
        try V:=Field(J,'retry_after'); if (V<>nil) and (V.JSONType=jtNumber) then Wait:=V.AsFloat;
        finally J.Free; end;
      except on E:ESafeError do Wait:=1; end;
      Require((Wait>=0) and (Wait<=5),'Discord rate limit is too long for the bounded retry budget.');
      MS:=Ceil(Wait*1000)+50; Sleep(MS); Continue;
    end;
    if (R.Status>=500) and (Attempt<2) then begin Sleep(250*(Attempt+1)); Continue; end;
    raise ESafeError.CreateFmt('Discord delivery failed (HTTP %d).',[R.Status]);
  end;
  raise ESafeError.Create('Discord delivery retry budget exhausted.');
end;
procedure EditOriginal(C:TBotConfig; H:TTransport; const Token,Text:string);
var Q:THttpRequest; J:TJSONObject;
begin
  Q:=Default(THttpRequest); Q.Method:='PATCH'; Q.MaxBytes:=262144;
  Q.URL:='https://discord.com/api/v10/webhooks/'+C.ApplicationID+'/'+URLPart(Token)+'/messages/@original';
  J:=MessageData(Text);
  try Q.Body:=J.AsJSON; finally J.Free; end;
  Deliver(H,Q);
end;
procedure RegisterCommands(C:TBotConfig; H:TTransport);
var Q:THttpRequest; J:TJSONArray; G:TJSONData; I:Integer;
begin
  Q:=Default(THttpRequest); Q.Method:='PUT'; Q.MaxBytes:=1048576;
  SetLength(Q.Headers,1); Q.Headers[0]:='Authorization: Bot '+C.BotToken;
  J:=CommandSchema;
  try Q.Body:=J.AsJSON; finally J.Free; end;
  G:=C.Guilds;
  for I:=0 to G.Count-1 do begin
    Q.URL:='https://discord.com/api/v10/applications/'+C.ApplicationID+'/guilds/'+Value(G.Items[I],'id','')+'/commands';
    Deliver(H,Q); WriteLn('Registered guild commands for '+Value(G.Items[I],'id','')+'.');
  end;
end;
end.
