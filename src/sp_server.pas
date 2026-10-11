unit sp_server;
{$mode objfpc}{$H+}
interface
uses SysUtils, Classes, fphttpserver, ssockets, sp_config, sp_http, sp_state, sp_providers, sp_engine;
type
  TBoundedConnection=class(TFPHTTPConnection)
  protected
    procedure ReadRequestContent(ARequest:TFPHTTPConnectionRequest); override;
    procedure SetupSocket; override;
  end;
  TBoundedServer=class(TFPHTTPServer)
  protected
    function CreateConnection(Data:TSocketStream):TFPHTTPConnection; override;
    procedure DoConnect(Sender:TObject; Data:TSocketStream); override;
  public
    property Address;
    function OpenConnections:Integer;
  end;
  TSentinelService=class
  private
    FServer:TBoundedServer;
    FConfig:TBotConfig; FTransport:TTransport;
    FState:TBotState; FProviders:TProviderHub; FEngine:TCommandEngine;
    procedure Handle(Sender:TObject; var Request:TFPHTTPConnectionRequest; var Response:TFPHTTPConnectionResponse);
    procedure RequestError(Sender:TObject; E:Exception);
    procedure Idle(Sender:TObject);
  public
    constructor Create(C:TBotConfig; Transport:TTransport);
    destructor Destroy; override;
    procedure Run;
  end;
implementation
uses BaseUnix, fpjson, sp_common, sp_crypto, sp_commands, sp_discord;
var Stopping:LongInt=0;
procedure StopSignal(Sig:LongInt); cdecl;
begin Stopping:=1; end;
type
  TJob=class(TThread)
  private
    FService:TSentinelService;
    FID,FGuild,FUser,FToken:string;
    FCommand:TCommandInput;
  protected
    procedure Execute; override;
  public
    constructor Create(S:TSentinelService; const ID,GuildID,UserID,Token:string; const Cmd:TCommandInput);
  end;
constructor TJob.Create(S:TSentinelService; const ID,GuildID,UserID,Token:string; const Cmd:TCommandInput);
begin
  inherited Create(True); FreeOnTerminate:=False;
  FService:=S; FID:=ID; FGuild:=GuildID; FUser:=UserID; FToken:=Token; FCommand:=Cmd;
end;
procedure TJob.Execute;
var Text,Outcome,CommandName:string; Started:QWord;
begin
  if Terminated then Exit; {a deferred acknowledgement failed before Start}
  Started:=GetTickCount64; CommandName:=FCommand.GroupName+' '+FCommand.Sub;
  try
    FService.FState.Audit(FID,FGuild,FUser,CommandName,'started',0);
    Outcome:='ok';
    try Text:=FService.FEngine.Run(FGuild,FCommand);
    except
      on E:ESafeError do begin Text:='Request could not be completed: '+E.Message; Outcome:='handled_error'; end;
      on E:Exception do begin Text:='Internal error. Reference: '+FID; Outcome:='internal_error'; end;
    end;
    try EditOriginal(FService.FConfig,FService.FTransport,FToken,Text);
    except on E:Exception do Outcome:='delivery_failed'; end;
    FService.FState.Audit(FID,FGuild,FUser,CommandName,Outcome,GetTickCount64-Started);
  finally
    FToken:=''; FService.FState.Finish;
  end;
end;
procedure TBoundedConnection.SetupSocket;
begin inherited SetupSocket; Socket.IOTimeout:=5000; end;
procedure TBoundedConnection.ReadRequestContent(ARequest:TFPHTTPConnectionRequest);
var Reply:string;
begin
  if (ARequest.ContentLength<0) or (ARequest.ContentLength>65536) or
     (ARequest.GetFieldByName('Transfer-Encoding')<>'') then begin
    Reply:='HTTP/1.1 413 Payload Too Large'+#13#10+'Content-Length: 0'+#13#10+'Connection: close'+#13#10#13#10;
    Socket.WriteBuffer(Reply[1],Length(Reply));
    raise EHTTPServer.Create('Unsupported request size or transfer encoding.');
  end;
  inherited ReadRequestContent(ARequest);
end;
function TBoundedServer.CreateConnection(Data:TSocketStream):TFPHTTPConnection;
begin Result:=TBoundedConnection.Create(Self,Data); end;
procedure TBoundedServer.DoConnect(Sender:TObject; Data:TSocketStream);
begin
  if ConnectionCount>=32 then begin Data.Free; Exit; end;
  inherited DoConnect(Sender,Data);
end;
function TBoundedServer.OpenConnections:Integer;
begin Result:=ConnectionCount; end;
constructor TSentinelService.Create(C:TBotConfig; Transport:TTransport);
begin
  inherited Create; FConfig:=C; FTransport:=Transport;
  FState:=TBotState.Create; FProviders:=TProviderHub.Create(C,Transport);
  FEngine:=TCommandEngine.Create(C,FProviders,Transport,FState);
  FServer:=TBoundedServer.Create(nil); FServer.Address:='0.0.0.0'; FServer.Port:=C.Port;
  FServer.Threaded:=True; FServer.QueueSize:=32; FServer.LookupHostNames:=False;
  FServer.ServerBanner:='Sentinel'; FServer.OnRequest:=@Handle;
  FServer.OnRequestError:=@RequestError; FServer.AcceptIdleTimeout:=500; FServer.OnAcceptIdle:=@Idle;
end;
destructor TSentinelService.Destroy;
begin
  FServer.Free;
  while FState.Jobs>0 do Sleep(20);
  FEngine.Free; FProviders.Free; FState.Free; inherited Destroy;
end;
procedure TSentinelService.Idle(Sender:TObject);
begin if Stopping<>0 then FServer.Active:=False; end;
procedure TSentinelService.RequestError(Sender:TObject; E:Exception);
begin {Never log exception messages: they may contain headers or request contents.}
  FState.Audit('','','','http','request_error',0);
end;
procedure TSentinelService.Handle(Sender:TObject; var Request:TFPHTTPConnectionRequest; var Response:TFPHTTPConnectionResponse);
var J,M,V:TJSONData; ID,GuildID,UserID,Token,Body:string; Cmd:TCommandInput;
    Admission:TAdmission; Job:TJob;
  procedure HTTPError(Code:Integer; const Msg:string);
  var O:TJSONObject;
  begin
    Response.Code:=Code; O:=TJSONObject.Create(['error',Msg]);
    try Response.Content:=O.AsJSON; finally O.Free; end;
  end;
begin
  Response.ContentType:='application/json; charset=utf-8'; Response.CustomHeaders.Values['Cache-Control']:='no-store';
  Response.CustomHeaders.Values['X-Content-Type-Options']:='nosniff';
  if (Request.Method='GET') and (Request.URI='/healthz') then begin
    Response.Content:='{"status":"ok","service":"sentinel-pascal"}'; Exit;
  end;
  if Request.URI<>'/interactions' then begin HTTPError(404,'not found'); Exit; end;
  if Request.Method<>'POST' then begin HTTPError(405,'POST required'); Exit; end;
  if Stopping<>0 then begin HTTPError(503,'shutting down'); Exit; end;
  Body:=Request.Content;
  if (Length(Body)=0) or (Length(Body)>65536) then begin HTTPError(413,'invalid body size'); Exit; end;
  if not VerifyDiscord(FConfig.PublicKey,Request.GetCustomHeader('X-Signature-Ed25519'),
    Request.GetCustomHeader('X-Signature-Timestamp'),Body,UnixNow) then begin
    HTTPError(401,'invalid interaction signature'); Exit;
  end;
  J:=nil;
  try
    try
      J:=ParseJSONSafe(Body);
      Require((J<>nil) and (J.JSONType=jtObject),'Expected an interaction object.');
      if Value(J,'type','')='1' then begin Response.Content:='{"type":1}'; Exit; end;
      Require(Value(J,'type','')='2','Only slash commands are supported.');
      if Value(J,'application_id','')<>FConfig.ApplicationID then begin HTTPError(401,'wrong application'); Exit; end;
      ID:=Value(J,'id',''); GuildID:=Value(J,'guild_id',''); M:=Field(J,'member');
      UserID:=Value(Field(M,'user'),'id','');
      Require(IsSnowflake(ID) and IsSnowflake(UserID) and IsSnowflake(GuildID),'Guild-only interaction required.');
      Cmd:=ParseCommand(Field(J,'data'));
      if not FConfig.Authorized(GuildID,Field(M,'roles'),Cmd.GroupName='pentest') then begin
        Response.Content:=ImmediateResponse('Access denied. An allowlisted guild role is required; pentest also needs a pentest role.');
        FState.Audit(ID,GuildID,UserID,Cmd.GroupName+' '+Cmd.Sub,'denied',0); Exit;
      end;
      V:=Field(J,'token'); Require((V<>nil) and (V.JSONType=jtString),'Missing interaction token.');
      Token:=V.AsString; Require((Length(Token)>0) and (Length(Token)<=512),'Invalid interaction token.');
      Admission:=FState.Admit(ID,UserID);
      case Admission of
        adDuplicate:begin Response.Content:='{"type":5,"data":{"flags":64}}'; Exit; end;
        adBusy:begin Response.Content:=ImmediateResponse('All worker slots are busy. Try again shortly.'); Exit; end;
        adRateLimited:begin Response.Content:=ImmediateResponse('Rate limit: at most five commands per user per minute.'); Exit; end;
      end;
      Job:=nil;
      try
        Job:=TJob.Create(Self,ID,GuildID,UserID,Token,Cmd);
        Response.Content:='{"type":5,"data":{"flags":64}}';
        Response.SendContent; {acknowledge before doing any provider I/O}
        Job.FreeOnTerminate:=True; Job.Start;
      except
        if Job<>nil then begin Job.FreeOnTerminate:=False; Job.Free; end;
        FState.Cancel(ID); raise;
      end;
    except
      on E:ESafeError do if not Response.ContentSent then Response.Content:=ImmediateResponse(E.Message);
      on E:Exception do if not Response.ContentSent then HTTPError(500,'internal request error');
    end;
  finally J.Free; end;
end;
procedure TSentinelService.Run;
begin
  Stopping:=0; fpSignal(SIGTERM,@StopSignal); fpSignal(SIGINT,@StopSignal); fpSignal(SIGPIPE,SignalHandler(SIG_IGN));
  WriteLn('Sentinel listening on 0.0.0.0:'+IntToStr(FConfig.Port)+' behind a required HTTPS reverse proxy.'); Flush(Output);
  FServer.Active:=True;
  while FServer.OpenConnections>0 do Sleep(20);
  while FState.Jobs>0 do Sleep(20);
end;
end.
