program test_server;
{$mode objfpc}{$H+}
{Test-only executable. It cannot make outbound HTTP calls; never deploy it.}
uses cthreads, SysUtils, Classes, SyncObjs, fpjson, sp_common, sp_config, sp_crypto, sp_http, sp_server;
type
  TRecordingTransport=class(TTransport)
  private Lock:TCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;
    function Send(const R:THttpRequest):THttpResponse; override;
  end;
constructor TRecordingTransport.Create;
begin inherited Create; Lock:=TCriticalSection.Create; end;
destructor TRecordingTransport.Destroy;
begin Lock.Free; inherited Destroy; end;
function TRecordingTransport.Send(const R:THttpRequest):THttpResponse;
var J:TJSONObject; S,Path:string; F:TFileStream;
begin
  Result:=Default(THttpResponse); Result.Status:=200;
  if Pos('api.ffraud.com',R.URL)>0 then Result.Body:='{"success":true,"fraud_score":0,"risk":"none","vpn":false}'
  else Result.Body:='{}';
  J:=TJSONObject.Create(['method',R.Method,'url',R.URL,'body',R.Body]);
  try S:=J.AsJSON+#10; finally J.Free; end;
  Lock.Enter;
  try
    Path:=GetEnvironmentVariable('TEST_RECORD_PATH');
    if FileExists(Path) then F:=TFileStream.Create(Path,fmOpenReadWrite or fmShareDenyNone)
    else F:=TFileStream.Create(Path,fmCreate);
    try F.Seek(0,soEnd); F.WriteBuffer(S[1],Length(S)); finally F.Free; end;
  finally Lock.Leave; end;
end;
var C:TBotConfig; H:TRecordingTransport; S:TSentinelService;
begin
  InitCrypto;
  C:=TBotConfig.FromJSON('{"guilds":[{"id":"111111111111111111","roles":["222222222222222222"],"pentest_roles":["333333333333333333"]}],"targets":[]}');
  C.ApplicationID:='444444444444444444'; C.PublicKey:=GetEnvironmentVariable('TEST_PUBLIC_KEY');
  C.Port:=StrToIntDef(GetEnvironmentVariable('TEST_PORT'),18080); C.Validate('server');
  H:=TRecordingTransport.Create; S:=TSentinelService.Create(C,H);
  try S.Run; finally S.Free; H.Free; C.Free; end;
end.
