unit sp_state;
{$mode objfpc}{$H+}
interface
uses SysUtils, Classes, SyncObjs, fpjson, sp_common;
type
  TAdmission = (adAccepted, adDuplicate, adBusy, adRateLimited);
  TWindow = class
    UntilTick: QWord;
    Count: Integer;
  end;
  TBotState = class
  private
    FLock: TCriticalSection;
    FSeen,FUsers,FTargets: TStringList;
    FJobs: Integer;
    procedure Prune(L: TStringList; Tick: QWord);
  public
    constructor Create;
    destructor Destroy; override;
    function Admit(const ID,UserID: string): TAdmission;
    procedure Finish;
    procedure Cancel(const ID:string);
    function Jobs: Integer;
    function TakeTarget(const GuildID,Alias: string): Boolean;
    procedure Audit(const ID,GuildID,UserID,Command,Outcome: string; ElapsedMS: QWord);
  end;
implementation
constructor TBotState.Create;
begin
  inherited Create; FLock:=TCriticalSection.Create;
  FSeen:=TStringList.Create; FUsers:=TStringList.Create; FTargets:=TStringList.Create;
end;
destructor TBotState.Destroy;
  procedure Clear(L:TStringList);
  var I:Integer;
  begin for I:=0 to L.Count-1 do L.Objects[I].Free; L.Free; end;
begin Clear(FSeen); Clear(FUsers); Clear(FTargets); FLock.Free; inherited Destroy; end;
procedure TBotState.Prune(L: TStringList; Tick: QWord);
var I:Integer;
begin
  for I:=L.Count-1 downto 0 do
    if TWindow(L.Objects[I]).UntilTick<=Tick then begin L.Objects[I].Free; L.Delete(I); end;
end;
function TBotState.Admit(const ID,UserID: string): TAdmission;
var Tick:QWord; I:Integer; W:TWindow;
begin
  FLock.Enter;
  try
    Tick:=GetTickCount64; Prune(FSeen,Tick); Prune(FUsers,Tick);
    if FSeen.IndexOf(ID)>=0 then Exit(adDuplicate);
    if (FJobs>=4) or (FSeen.Count>=4096) or (FUsers.Count>=2048) then Exit(adBusy);
    I:=FUsers.IndexOf(UserID);
    if I<0 then begin
      W:=TWindow.Create; W.UntilTick:=Tick+60000;
      I:=FUsers.AddObject(UserID,W);
    end;
    W:=TWindow(FUsers.Objects[I]);
    if W.Count>=5 then Exit(adRateLimited);
    Inc(W.Count);
    W:=TWindow.Create; W.UntilTick:=Tick+600000; FSeen.AddObject(ID,W);
    Inc(FJobs); Result:=adAccepted;
  finally FLock.Leave; end;
end;
procedure TBotState.Finish;
begin FLock.Enter; try if FJobs>0 then Dec(FJobs); finally FLock.Leave; end; end;
procedure TBotState.Cancel(const ID:string);
var I:Integer;
begin
  FLock.Enter;
  try
    I:=FSeen.IndexOf(ID);
    if I>=0 then begin FSeen.Objects[I].Free; FSeen.Delete(I); end;
    if FJobs>0 then Dec(FJobs);
  finally FLock.Leave; end;
end;
function TBotState.Jobs: Integer;
begin FLock.Enter; try Result:=FJobs; finally FLock.Leave; end; end;
function TBotState.TakeTarget(const GuildID,Alias: string): Boolean;
var K:string; W:TWindow;
begin
  FLock.Enter;
  try
    Prune(FTargets,GetTickCount64); K:=GuildID+'/'+Alias;
    if (FTargets.IndexOf(K)>=0) or (FTargets.Count>=100) then Exit(False);
    W:=TWindow.Create; W.UntilTick:=GetTickCount64+60000; FTargets.AddObject(K,W); Result:=True;
  finally FLock.Leave; end;
end;
procedure TBotState.Audit(const ID,GuildID,UserID,Command,Outcome: string; ElapsedMS: QWord);
var J:TJSONObject;
begin
  J:=TJSONObject.Create(['time',UTCStamp,'interaction',ID,'guild',GuildID,'actor',UserID,
    'command',Command,'outcome',Outcome,'elapsed_ms',Int64(ElapsedMS)]);
  try
    FLock.Enter;
    try WriteLn(J.AsJSON); Flush(Output); finally FLock.Leave; end;
  finally J.Free; end;
end;
end.
