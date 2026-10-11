unit sp_config;
{$mode objfpc}{$H+}
interface
uses SysUtils, Classes, fpjson, sp_common;
type
  TBotConfig = class
  private
    FRoot: TJSONData;
    FEnv: TStringList;
    function Setting(const Name: string): string;
    procedure ReadEnv(const FileName: string);
    procedure LoadSettings;
  public
    ApplicationID, PublicKey, BotToken, ShodanKey, FFraudKey, RLiveKey: string;
    RLiveMode: string;
    Port: Word;
    SearchEnabled: Boolean;
    constructor Create(const FileName: string; const EnvFile: string = '.env');
    constructor FromJSON(const S: string);
    destructor Destroy; override;
    procedure Validate(const Mode: string);
    function Guilds: TJSONData;
    function Authorized(const GuildID: string; Roles: TJSONData; Pentest: Boolean): Boolean;
    function Target(const GuildID, Alias: string): TScopeTarget;
    function ScopeSummary(const GuildID: string): string;
  end;
implementation
uses jsonparser;
constructor TBotConfig.Create(const FileName: string; const EnvFile: string);
begin
  inherited Create;
  FEnv := TStringList.Create;
  FEnv.CaseSensitive := True;
  ReadEnv(EnvFile);
  Require(FileExists(FileName),'Missing config.json. Copy config.example.json and configure your guild and roles.');
  try FRoot := GetJSON(ReadSmallFile(FileName));
  except raise ESafeError.Create('Invalid configuration JSON.'); end;
  LoadSettings;
end;
constructor TBotConfig.FromJSON(const S: string);
begin
  inherited Create;
  FEnv := TStringList.Create;
  FRoot := GetJSON(S);
  Port := 8080; RLiveMode := 'v2';
end;
destructor TBotConfig.Destroy;
begin FRoot.Free; FEnv.Free; inherited Destroy; end;
procedure TBotConfig.ReadEnv(const FileName: string);
var Lines: TStringList; Line,K,V: string; I,P: Integer;
begin
  if not FileExists(FileName) then Exit;
  Lines := TStringList.Create;
  try
    Lines.Text := ReadSmallFile(FileName);
    for I := 0 to Lines.Count-1 do begin
      Line := Trim(Lines[I]);
      if (Line = '') or (Line[1] = '#') then Continue;
      P := Pos('=',Line);
      Require(P > 1,'Invalid .env entry. Expected NAME=value.');
      K := Trim(Copy(Line,1,P-1)); V := Trim(Copy(Line,P+1,Length(Line)));
      if (Length(V) >= 2) and (V[1] in ['"','''']) and (V[Length(V)] = V[1]) then
        V := Copy(V,2,Length(V)-2);
      Require((Pos(#10,V)=0) and (Pos(#13,V)=0),'Multiline secrets are not supported.');
      FEnv.Values[K] := V;
    end;
  finally Lines.Free; end;
end;
function TBotConfig.Setting(const Name: string): string;
var I: Integer; S: string;
begin
  for I := 1 to GetEnvironmentVariableCount do begin
    S := GetEnvironmentString(I);
    if Copy(S,1,Length(Name)+1) = Name+'=' then Exit(Copy(S,Length(Name)+2,Length(S)));
  end;
  Result := FEnv.Values[Name];
end;
procedure TBotConfig.LoadSettings;
var P: Integer;
begin
  ApplicationID := Setting('DISCORD_APPLICATION_ID'); PublicKey := Setting('DISCORD_PUBLIC_KEY');
  BotToken := Setting('DISCORD_BOT_TOKEN'); ShodanKey := Setting('SHODAN_API_KEY');
  FFraudKey := Setting('FFRAUD_API_KEY'); RLiveKey := Setting('RANSOMWARE_LIVE_API_KEY');
  RLiveMode := LowerCase(Setting('RANSOMWARE_LIVE_MODE'));
  if RLiveMode = '' then RLiveMode := 'v2';
  SearchEnabled := LowerCase(Setting('SHODAN_SEARCH_ENABLED')) = 'true';
  P := StrToIntDef(Setting('PORT'),8080);
  Require((P >= 1024) and (P <= 65535),'PORT must be between 1024 and 65535.'); Port := P;
end;
function TBotConfig.Guilds: TJSONData;
begin Result := Field(FRoot,'guilds'); end;
procedure TBotConfig.Validate(const Mode: string);
var G,R,T: TJSONData; I,K: Integer; S: string; C: Char; D: TScopeTarget;
    Names: TStringList;
  procedure CheckSecret(const V: string);
  var Ch: Char;
  begin
    Require(Length(V) <= 512,'Configured secret exceeds size limit.');
    for Ch in V do Require(Ord(Ch) >= 33,'Secrets must not contain whitespace/control characters.');
  end;
begin
  Require((FRoot <> nil) and (FRoot.JSONType = jtObject),'Configuration must be an object.');
  Require(IsSnowflake(ApplicationID),'DISCORD_APPLICATION_ID must be a Discord application ID.');
  if Mode <> 'register' then begin
    Require(Length(PublicKey) = 64,'DISCORD_PUBLIC_KEY must be 64 hex characters.');
    for C in PublicKey do Require(C in ['0'..'9','a'..'f','A'..'F'],'Invalid Discord public key.');
  end else Require(BotToken <> '','DISCORD_BOT_TOKEN is required to register commands.');
  CheckSecret(BotToken); CheckSecret(ShodanKey); CheckSecret(FFraudKey); CheckSecret(RLiveKey);
  Require((RLiveMode = 'v2') or (RLiveMode = 'pro'),'RANSOMWARE_LIVE_MODE must be v2 or pro.');
  if RLiveMode = 'pro' then Require(RLiveKey <> '','Pro mode requires RANSOMWARE_LIVE_API_KEY.');
  G := Guilds;
  Require((G <> nil) and (G.JSONType = jtArray) and (G.Count > 0),'Configure at least one authorized guild.');
  Require(G.Count <= 50,'At most 50 guilds are supported per instance.');
  Names := TStringList.Create;
  try
    for I := 0 to G.Count-1 do begin
      S := Value(G.Items[I],'id',''); Require(IsSnowflake(S),'Invalid configured guild ID.');
      Require(Names.IndexOf(S) < 0,'Duplicate guild ID.'); Names.Add(S);
      R := Field(G.Items[I],'roles');
      Require((R <> nil) and (R.JSONType = jtArray) and (R.Count > 0),'Each guild needs a nonempty roles allowlist.');
      for K := 0 to R.Count-1 do Require(IsSnowflake(TextOf(R.Items[K],'')),'Invalid role ID.');
      R := Field(G.Items[I],'pentest_roles');
      Require((R <> nil) and (R.JSONType = jtArray),'Each guild needs a pentest_roles array (may be empty).');
      for K := 0 to R.Count-1 do Require(IsSnowflake(TextOf(R.Items[K],'')),'Invalid pentest role ID.');
    end;
    T := Field(FRoot,'targets');
    Require((T <> nil) and (T.JSONType = jtArray),'Configuration requires a targets array (empty disables checks).');
    Require(T.Count <= 100,'At most 100 explicit targets are supported.');
    Names.Clear;
    for I := 0 to T.Count-1 do begin
      S := Value(T.Items[I],'guild_id','') + '/' + Value(T.Items[I],'alias','');
      Require(Names.IndexOf(S) < 0,'Duplicate target alias in a guild.'); Names.Add(S);
      D := Target(Value(T.Items[I],'guild_id',''),Value(T.Items[I],'alias',''));
      Require(D.Alias <> '','Invalid target.');
    end;
  finally Names.Free; end;
end;
function TBotConfig.Authorized(const GuildID: string; Roles: TJSONData; Pentest: Boolean): Boolean;
var G,A: TJSONData; I: Integer; BaseOK,ActiveOK: Boolean;
  function Match(List: TJSONData): Boolean;
  var J,K: Integer;
  begin
    Result := False;
    if (List = nil) or (List.JSONType <> jtArray) then Exit;
    for J := 0 to List.Count-1 do
      for K := 0 to Roles.Count-1 do
        if TextOf(List.Items[J],'!') = TextOf(Roles.Items[K],'?') then Exit(True);
  end;
begin
  Result := False; G := Guilds;
  if (G = nil) or (G.JSONType <> jtArray) or (Roles = nil) or (Roles.JSONType <> jtArray) then Exit;
  for I := 0 to G.Count-1 do begin
    A := G.Items[I];
    if Value(A,'id','') <> GuildID then Continue;
    BaseOK := Match(Field(A,'roles')); ActiveOK := Match(Field(A,'pentest_roles'));
    Exit(BaseOK and ((not Pentest) or ActiveOK));
  end;
end;
function TBotConfig.Target(const GuildID, Alias: string): TScopeTarget;
var T,A,P,G: TJSONData; I,J,K,V: Integer; C: Char; KnownGuild: Boolean;
begin
  Result := Default(TScopeTarget);
  Require((Length(Alias) >= 1) and (Length(Alias) <= 32),'Target must be a configured alias.');
  for C in Alias do Require(C in ['a'..'z','0'..'9','-','_'],'Invalid target alias.');
  KnownGuild := False; G := Guilds;
  if (G <> nil) and (G.JSONType = jtArray) then
    for I := 0 to G.Count-1 do if Value(G.Items[I],'id','')=GuildID then KnownGuild := True;
  Require(KnownGuild,'Target guild is not authorized.');
  T := Field(FRoot,'targets');
  Require((T <> nil) and (T.JSONType = jtArray),'No authorized targets configured.');
  for I := 0 to T.Count-1 do begin
    A := T.Items[I];
    if (Value(A,'guild_id','') <> GuildID) or (Value(A,'alias','') <> Alias) then Continue;
    Result.Alias := Alias; Result.GuildID := GuildID;
    Result.Hostname := LowerCase(Value(A,'hostname',''));
    Result.IPv4 := Value(A,'ipv4',''); Result.Expires := Value(A,'expires','');
    Require(IsDomain(Result.Hostname),'Scope hostname must be a plain ASCII/punycode domain.');
    Require(IsPublicIPv4(Result.IPv4),'Scope IP must be an explicit public IPv4; special/private addresses are blocked.');
    Require(ValidDate(Result.Expires),'Scope needs an expires date (YYYY-MM-DD, inclusive UTC).');
    Require(Result.Expires >= Copy(UTCStamp,1,10),'Authorization expired. Renew the scope file and restart.');
    P := Field(A,'ports');
    Require((P <> nil) and (P.JSONType = jtArray) and (P.Count >= 1) and (P.Count <= 8),'Scope needs 1-8 explicit TCP ports.');
    SetLength(Result.Ports,P.Count);
    for J := 0 to P.Count-1 do begin
      Require(P.Items[J].JSONType = jtNumber,'Ports must be integers.');
      V := StrToIntDef(P.Items[J].AsString,0);
      Require((V >= 1) and (V <= 65535),'Port out of range.');
      for K := 0 to J-1 do Require(Result.Ports[K] <> V,'Duplicate scope port.');
      Result.Ports[J] := V;
    end;
    Exit;
  end;
  raise ESafeError.Create('Unknown target alias for this guild. Use /pentest scope.');
end;
function TBotConfig.ScopeSummary(const GuildID: string): string;
var T,A: TJSONData; I: Integer;
begin
  Result := 'Authorized targets (fixed IPs; no wildcards):' + #10;
  T := Field(FRoot,'targets');
  if (T <> nil) and (T.JSONType = jtArray) then
    for I := 0 to T.Count-1 do begin
      A := T.Items[I];
      if Value(A,'guild_id','')=GuildID then Result += Value(A,'alias') + ' | ' + Value(A,'hostname') +
        ' | ports ' + ArrayText(Field(A,'ports')) + ' | expires ' + Value(A,'expires') + #10;
    end;
  Result += 'Only perform checks covered by written authorization.';
end;
end.
