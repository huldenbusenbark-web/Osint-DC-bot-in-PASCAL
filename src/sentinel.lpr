program sentinel;
{$mode objfpc}{$H+}
uses cthreads, SysUtils, fpjson, sp_common, sp_config, sp_crypto, sp_http,
  sp_commands, sp_discord, sp_server;
var C:TBotConfig; H:TCurlTransport; Service:TSentinelService; Schema:TJSONArray;
    Mode,Path:string; HTTPReady:Boolean;
begin
  C:=nil; H:=nil; Service:=nil; HTTPReady:=False;
  try
    Mode:=ParamStr(1); Path:=ParamStr(2); if Path='' then Path:='config.json';
    if Mode='--commands' then begin
      Schema:=CommandSchema;
      try WriteLn(Schema.FormatJSON); finally Schema.Free; end;
    end else if (Mode='--serve') or (Mode='--check') or (Mode='--register') then begin
      InitCrypto; InitHTTP; HTTPReady:=True;
      C:=TBotConfig.Create(Path);
      if Mode='--register' then C.Validate('register') else C.Validate('server');
      if Mode='--check' then WriteLn('Configuration valid. No network checks or registration performed.')
      else begin
        H:=TCurlTransport.Create;
        if Mode='--register' then RegisterCommands(C,H)
        else begin Service:=TSentinelService.Create(C,H); Service.Run; end;
      end;
    end else begin
      WriteLn('Sentinel Pascal 1.0 - defensive OSINT Discord application');
      WriteLn('  sentinel --commands              Print guild command registration JSON');
      WriteLn('  sentinel --check [config.json]   Validate local configuration only');
      WriteLn('  sentinel --register [config.json]  REPLACE this app''s commands in configured guilds');
      WriteLn('  sentinel --serve [config.json]   Run the signed HTTP interaction endpoint');
      if (Mode<>'') and (Mode<>'--help') then ExitCode:=1;
    end;
  except
    on E:ESafeError do begin WriteLn(StdErr,'Error: '+E.Message); ExitCode:=1; end;
    on E:Exception do begin WriteLn(StdErr,'Startup failed. Check file permissions, configuration and native dependencies.'); ExitCode:=1; end;
  end;
  Service.Free; H.Free; C.Free;
  if HTTPReady then DoneHTTP;
end.
