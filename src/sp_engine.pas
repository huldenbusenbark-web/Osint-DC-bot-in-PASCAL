unit sp_engine;
{$mode objfpc}{$H+}
interface
uses SysUtils, sp_common, sp_config, sp_commands, sp_providers, sp_http, sp_state;
type
  TCommandEngine=class
  private
    FConfig:TBotConfig; FProviders:TProviderHub; FTransport:TTransport; FState:TBotState;
    function One(const Service,Action,Arg:string; Limit:Integer; MaxBytes:Integer=0):string;
  public
    constructor Create(C:TBotConfig; P:TProviderHub; H:TTransport; S:TBotState);
    function Run(const GuildID:string; const Cmd:TCommandInput):string;
  end;
implementation
uses sp_reports, sp_pentest;
constructor TCommandEngine.Create(C:TBotConfig; P:TProviderHub; H:TTransport; S:TBotState);
begin inherited Create; FConfig:=C; FProviders:=P; FTransport:=H; FState:=S; end;
function TCommandEngine.One(const Service,Action,Arg:string; Limit:Integer; MaxBytes:Integer):string;
var R:TApiReply;
begin
  R:=FProviders.Fetch(Service,Action,Arg,Limit);
  try
    Result:=RenderReply(Service,Action,Arg,R,Limit);
    if (MaxBytes>0) and (Length(Result)>MaxBytes) then
      Result:=ClipUTF8(Result,MaxBytes)+#10+'[section shortened]'+#10+ReplyMeta(R);
  finally R.JSON.Free; end;
end;
function TCommandEngine.Run(const GuildID:string; const Cmd:TCommandInput):string;
var T:TScopeTarget;
  function Partial(const Service,Action:string; Limit:Integer):string;
  begin
    try Result:=One(Service,Action,Cmd.Arg,Limit,650);
    except on E:ESafeError do Result:=Service+': '+E.Message; end;
  end;
begin
  case Cmd.GroupName of
    'help':Exit(HelpText);
    'status':begin
      Result:='Sentinel Pascal / capabilities'+#10+'FFraud: public API';
      if FConfig.FFraudKey<>'' then Result+=' (key configured)';
      Result+=#10+'Ransomware.live: '+FConfig.RLiveMode+#10+'RansomLook: public API'+#10;
      if FConfig.ShodanKey='' then Result+='Shodan: disabled (no key)' else Result+='Shodan: configured';
      if FConfig.SearchEnabled then Result+=' | search opted in' else Result+=' | search disabled';
      Result+=#10+'Worker slots in use: '+IntToStr(FState.Jobs)+'/4'+#10+
        'Private responses | 5 requests/user/min | 5-minute memory cache'+#10+
        'Active checks: explicit guild-scoped aliases only'+#10+
        'This is configuration status, not a provider health check.';
    end;
    'ffraud','rlive','rlook','shodan':Result:=One(Cmd.GroupName,Cmd.Sub,Cmd.Arg,Cmd.Limit);
    'intel':begin
      if Cmd.Sub='ip' then Result:=Partial('ffraud','ip',5)+#10+#10+Partial('shodan','host',5)
      else Result:=Partial('rlive','search',2)+#10+#10+Partial('rlook','search',2);
    end;
    'pentest':begin
      if Cmd.Sub='scope' then Exit(FConfig.ScopeSummary(GuildID));
      T:=FConfig.Target(GuildID,Cmd.Arg);
      Require(FState.TakeTarget(GuildID,T.Alias),'Target cooldown: one check per target per 60 seconds.');
      case Cmd.Sub of
        'ports':Result:=CheckPorts(T);
        'headers':Result:=CheckHTTPS(T,False,FTransport);
        'tls':Result:=CheckHTTPS(T,True,FTransport);
        'dns':Result:=CheckDNS(T,FProviders);
        else raise ESafeError.Create('Unknown pentest operation.');
      end;
    end;
    else raise ESafeError.Create('Unknown command.');
  end;
end;
end.
