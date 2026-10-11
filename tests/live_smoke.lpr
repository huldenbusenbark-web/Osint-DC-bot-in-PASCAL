program live_smoke;
{$mode objfpc}{$H+}
{Optional live, public-API schema/transport checks. Never runs a target port/TLS scan.}
uses cthreads, SysUtils, sp_common, sp_config, sp_crypto, sp_http, sp_providers, sp_reports;
var C:TBotConfig; H:TCurlTransport; P:TProviderHub; Plan:TApiPlan;
    R:TApiReply; HR:THttpResponse; S:string; Passed,Failed:Integer;
procedure Smoke(const Service,Action,Arg:string);
begin
  try
    R:=P.Fetch(Service,Action,Arg,1);
    try S:=RenderReply(Service,Action,Arg,R,1); Require(S<>'','Empty formatted response.');
    finally R.JSON.Free; end;
    Inc(Passed); WriteLn('PASS live ',Service,' ',Action,' schema and HTTPS transport');
  except on E:Exception do begin Inc(Failed); WriteLn('FAIL live ',Service,': ',E.Message); end; end;
end;
begin
  InitCrypto; InitHTTP; C:=TBotConfig.FromJSON('{"guilds":[],"targets":[]}');
  H:=TCurlTransport.Create; P:=TProviderHub.Create(C,H);
  try
    {A normal public API GET, with TLS metadata collected from that same connection.}
    try
      Plan:=P.Plan('ffraud','ip','1.1.1.1',1); Plan.Request.CertificateInfo:=True;
      HR:=H.Send(Plan.Request); Require(HR.Status=200,'FFraud did not return HTTP 200.');
      R:=Default(TApiReply); R.JSON:=ParseJSONSafe(HR.Body); R.Source:='FFraud'; R.FetchedUTC:=UTCStamp;
      try S:=RenderReply('ffraud','ip','1.1.1.1',R,1); finally R.JSON.Free; end;
      Require(HR.Certificate<>'','libcurl did not supply certificate metadata.');
      Inc(Passed); WriteLn('PASS live FFraud schema, verified HTTPS and libcurl certificate metadata');
    except on E:Exception do begin Inc(Failed); WriteLn('FAIL live FFraud: ',E.Message); end; end;
    Smoke('rlive','recent',''); Smoke('rlook','recent','');
    WriteLn('LIVE RESULT ',Passed,' passed; ',Failed,' failed. No authenticated APIs tested.');
    if Failed>0 then ExitCode:=1;
  finally P.Free; H.Free; C.Free; DoneHTTP; end;
end.
