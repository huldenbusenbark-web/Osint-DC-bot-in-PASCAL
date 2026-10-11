program test_suite;
{$mode objfpc}{$H+}{$codepage utf8}
uses cthreads, SysUtils, Classes, ctypes, fpjson, sp_common, sp_config, sp_crypto,
  sp_commands, sp_http, sp_providers, sp_reports, sp_pentest, sp_state, sp_engine, sp_discord;
const
  Guild='111111111111111111'; Role='222222222222222222'; ActiveRole='333333333333333333';
  BaseConfig='{"guilds":[{"id":"111111111111111111","roles":["222222222222222222"],'+
    '"pentest_roles":["333333333333333333"]}],"targets":[]}';
  ScopeConfig='{"guilds":[{"id":"111111111111111111","roles":["222222222222222222"],'+
    '"pentest_roles":["333333333333333333"]}],"targets":[{"alias":"edge","guild_id":"111111111111111111",'+
    '"hostname":"example.com","ipv4":"93.184.216.34","ports":[80,443],"expires":"2999-12-31"}]}';
type
  TMock=class(TTransport)
    Count:Integer;
    Body,Headers:string;
    Status:Integer;
    Last:THttpRequest;
    constructor Create;
    function Send(const R:THttpRequest):THttpResponse; override;
  end;
var Passed,Failed:Integer;
function crypto_sign_seed_keypair(PK,SK,Seed:Pointer):cint; cdecl; external 'sodium';
function crypto_sign_detached(Sig:Pointer; SigLen:Pointer; Msg:Pointer; N:QWord; SK:Pointer):cint; cdecl; external 'sodium';
constructor TMock.Create;
begin inherited Create; Status:=200; Body:='{}'; end;
function TMock.Send(const R:THttpRequest):THttpResponse;
begin
  Inc(Count); Last:=R; Result:=Default(THttpResponse);
  Result.Status:=Status; Result.Body:=Body; Result.Headers:=Headers; Result.PrimaryIP:=R.PinnedIPv4;
end;
procedure Check(B:Boolean; const Name:string);
begin
  if B then begin Inc(Passed); WriteLn('PASS ',Name); end
  else begin Inc(Failed); WriteLn('FAIL ',Name); end;
end;
function Hex(P:Pointer; N:Integer):string;
var I:Integer;
begin Result:=''; for I:=0 to N-1 do Result+=IntToHex(PByte(P)[I],2); end;
procedure PlanDenied(H:TProviderHub; const Service,Action,Arg,Name:string);
var Blocked:Boolean; P:TApiPlan;
begin
  Blocked:=False;
  try P:=H.Plan(Service,Action,Arg,5); if P.Source='' then Write('');
  except on E:ESafeError do Blocked:=True; end;
  Check(Blocked,Name);
end;
procedure ParseDenied(const S,Name:string);
var J:TJSONData; C:TCommandInput; Blocked:Boolean;
begin
  J:=ParseJSONSafe(S); Blocked:=False;
  try
    try C:=ParseCommand(J); if C.Limit=0 then Write('');
    except on E:ESafeError do Blocked:=True; end;
  finally J.Free; end;
  Check(Blocked,Name);
end;
procedure Basics;
var S:string; J:TJSONData; O:TJSONObject; Blocked:Boolean;
begin
  Check(URLPart('a/b ?&+%')='a%2Fb%20%3F%26%2B%25','URL parameters cannot inject paths/queries');
  Check(IsDomain('xn--bcher-kva.example'),'punycode hostname accepted');
  Check(not IsDomain('https://example.com'),'URL not accepted as hostname');
  Check(not IsDomain('example.com@127.0.0.1'),'userinfo hostname rejected');
  Check(not IsDomain('a..com'),'empty DNS label rejected');
  Check(not IsDomain('-a.example'),'bad label rejected');
  Check(not IsDomain('1.1.1.1'),'numeric address not accepted as scoped TLS hostname');
  Check(IsIP('2606:4700:4700::1111'),'IPv6 syntax supported for passive lookups');
  Check(IsPublicIPv4('1.1.1.1'),'public canonical IPv4 accepted');
  Check(not IsPublicIPv4('127.0.0.1'),'loopback blocked');
  Check(not IsPublicIPv4('169.254.169.254'),'metadata/link-local blocked');
  Check(not IsPublicIPv4('10.1.2.3'),'private network blocked');
  Check(not IsPublicIPv4('100.64.0.1'),'CGNAT blocked');
  Check(not IsPublicIPv4('198.18.0.1'),'benchmark network blocked');
  Check(not IsPublicIPv4('203.0.113.1'),'documentation addresses blocked');
  Check(not IsPublicIPv4('224.0.0.1'),'multicast blocked');
  Check(not IsPublicIPv4('01.1.1.1'),'noncanonical IPv4 blocked');
  Check(not IsPublicIPv4('1.1.1.1'+#0+'evil'),'IPv4 NUL suffix blocked');
  Check(not IsPublicIP('::ffff:127.0.0.1'),'IPv4-mapped IPv6 blocked');
  Check(not IsPublicIP('2001:db8::1'),'IPv6 documentation range blocked');
  Check(not IsPublicIP('fc00::1'),'IPv6 private range blocked');
  Check(IsPublicIP('2606:4700:4700::1111'),'global IPv6 accepted');
  Check(not IsPublicIP('2606:4700::1111'+#0+'x'),'IPv6 NUL suffix blocked');
  Check(ValidDate('2028-02-29') and not ValidDate('2027-02-29'),'date validation handles leap years');
  S:=#195#169#195#169;
  Check(ClipUTF8(S,3)=Copy(S,1,2),'UTF-8 truncation keeps complete codepoints');
  O:=MessageData('a``` @everyone'+#0+StringOfChar('x',2200));
  try
    S:=O.Get('content',''); Check(Length(S)<2000,'Discord content bounded');
    Check(Pos('a''''''',S)>0,'untrusted code fences neutralized');
    Check(Field(Field(O,'allowed_mentions'),'parse').Count=0,'mentions disabled');
  finally O.Free; end;
  J:=ParseJSONSafe(ImmediateResponse('hello'));
  try Check(Value(Field(J,'data'),'flags')='64','immediate replies ephemeral'); finally J.Free; end;
  Blocked:=False;
  try J:=ParseJSONSafe(StringOfChar('[',49)+StringOfChar(']',49)); J.Free;
  except on E:ESafeError do Blocked:=True; end;
  Check(Blocked,'excessively nested JSON rejected');
  Blocked:=False;
  try J:=ParseJSONSafe('{broken'); J.Free; except on E:ESafeError do Blocked:=True; end;
  Check(Blocked,'malformed JSON yields safe error');
end;
procedure Signatures;
var Seed,PK:array[0..31] of Byte; SK,Sig:array[0..63] of Byte; SigLen:QWord;
    TS,Body,Msg,PKH,SH:string; I:Integer;
begin
  for I:=0 to 31 do Seed[I]:=I;
  crypto_sign_seed_keypair(@PK,@SK,@Seed); TS:='1800000000'; Body:='{"type":1,"text":"é"}'; Msg:=TS+Body;
  crypto_sign_detached(@Sig,@SigLen,PChar(Msg),Length(Msg),@SK); PKH:=Hex(@PK,32); SH:=Hex(@Sig,64);
  Check(VerifyDiscord(PKH,SH,TS,Body,1800000000),'valid Ed25519 signature over exact UTF-8 body');
  Check(not VerifyDiscord(PKH,SH,TS,Body+' ',1800000000),'body modification rejected');
  Check(not VerifyDiscord(PKH,SH,TS,Body,1800000301),'stale signed request rejected');
  Check(not VerifyDiscord(PKH,SH,TS,Body,1799999969),'future signed request rejected');
  Check(not VerifyDiscord(PKH,'abc',TS,Body,1800000000),'malformed signature rejected');
  Check(not VerifyDiscord(PKH,SH,'1e9',Body,1800000000),'nonnumeric timestamp rejected');
  Check(not VerifyDiscord(StringOfChar('0',64),SH,TS,Body,1800000000),'wrong public key rejected');
end;
procedure ConfigAndScope;
var C,D:TBotConfig; R:TJSONArray; T:TScopeTarget; Q:THttpRequest; Blocked:Boolean;
begin
  C:=TBotConfig.FromJSON(ScopeConfig); R:=TJSONArray.Create([Role]);
  try
    Check(C.Authorized(Guild,R,False),'authorized role accepted');
    Check(not C.Authorized('999999999999999999',R,False),'cross-guild access rejected');
    Check(not C.Authorized(Guild,R,True),'pentest needs extra role'); R.Add(ActiveRole);
    Check(C.Authorized(Guild,R,True),'pentest role accepted with base role');
    R.Delete(0); Check(not C.Authorized(Guild,R,True),'pentest role alone does not bypass base role');
    T:=C.Target(Guild,'edge'); Check((Length(T.Ports)=2) and HasPort(T,443),'explicit scope loaded');
    Q:=HTTPSPlan(T,True);
    Check(Q.HeadOnly and (Q.Method='HEAD') and (Q.URL='https://example.com/'),'HTTPS check is root HEAD only');
    Check((Q.PinnedIPv4=T.IPv4) and (Q.PinnedPort=443) and Q.CertificateInfo,'TLS request carries exact IP pin and certificate flag');
    Blocked:=False;
    try T:=C.Target('999999999999999999','edge'); except on E:ESafeError do Blocked:=True; end;
    Check(Blocked,'target scope cannot cross guild boundary');
    Blocked:=False;
    try T:=C.Target(Guild,'https://evil.example'); except on E:ESafeError do Blocked:=True; end;
    Check(Blocked,'target argument cannot be arbitrary URL');
    C.ApplicationID:='444444444444444444'; C.PublicKey:=StringOfChar('a',64); C.Validate('server');
    Check(True,'complete config validation passes');
  finally R.Free; C.Free; end;
  D:=TBotConfig.FromJSON(StringReplace(ScopeConfig,'93.184.216.34','127.0.0.1',[]));
  try
    Blocked:=False; try T:=D.Target(Guild,'edge'); except on E:ESafeError do Blocked:=True; end;
    Check(Blocked,'private target config fails closed');
  finally D.Free; end;
  D:=TBotConfig.FromJSON(StringReplace(ScopeConfig,'2999-12-31','2000-01-01',[]));
  try
    Blocked:=False; try T:=D.Target(Guild,'edge'); except on E:ESafeError do Blocked:=True; end;
    Check(Blocked,'expired authorization fails closed');
  finally D.Free; end;
end;
procedure Commands;
var J:TJSONData; C:TCommandInput; I,N:Integer;
begin
  J:=CommandSchema;
  try
    Check(J.Count=8,'eight top-level Discord command groups'); N:=0;
    for I:=0 to J.Count-1 do begin
      if Field(J.Items[I],'options')=nil then Inc(N) else Inc(N,Field(J.Items[I],'options').Count);
      Check(Value(J.Items[I],'default_member_permissions')='0','commands hidden by default: '+Value(J.Items[I],'name'));
    end;
    Check(N=25,'25 leaf commands registered');
  finally J.Free; end;
  J:=ParseJSONSafe('{"name":"ffraud","options":[{"name":"ip","type":1,"options":[{"name":"address","type":3,"value":"1.1.1.1"}]}]}');
  try C:=ParseCommand(J); Check((C.Sub='ip') and (C.Arg='1.1.1.1'),'slash command parsed'); finally J.Free; end;
  ParseDenied('{"name":"shell"}','no arbitrary shell command');
  ParseDenied('{"name":"shodan","options":[{"type":1,"name":"scan"}]}','no active Shodan scan command');
  ParseDenied('{"name":"rlook","options":[{"type":1,"name":"recent","options":[{"name":"limit","type":4,"value":11}]}]}','result limit bounded');
  ParseDenied('{"name":"rlook","options":[{"type":1,"name":"recent","options":[{"name":"limit","type":4,"value":1.5}]}]}','fractional limit rejected');
  ParseDenied('{"name":"ffraud","options":[{"type":1,"name":"ip"}]}','missing required argument rejected');
  ParseDenied('{"name":"help","options":[{"name":"extra","type":3,"value":"x"}]}','unknown options rejected');
end;
procedure Providers;
var C:TBotConfig; M:TMock; H:TProviderHub; P:TApiPlan; R:TApiReply; J:TJSONData;
    S:string; Blocked:Boolean;
begin
  C:=TBotConfig.FromJSON(BaseConfig); M:=TMock.Create; H:=TProviderHub.Create(C,M);
  try
    P:=H.Plan('ffraud','ip','1.1.1.1',5);
    Check(P.Request.URL='https://api.ffraud.com/public/ip/1.1.1.1','documented FFraud public IP path');
    C.FFraudKey:='test_key'; P:=H.Plan('ffraud','ip','1.1.1.1',5);
    Check((P.Request.Method='POST') and (P.Request.URL='https://api.ffraud.com/v1/ip/check'),'documented keyed FFraud POST');
    Check(P.Request.Headers[0]='X-API-Key: test_key','FFraud key in header');
    J:=ParseJSONSafe(P.Request.Body); try Check(Value(J,'ip')='1.1.1.1','FFraud POST JSON body'); finally J.Free; end;
    P:=H.Plan('ffraud','email','test@example.com',5); Check(Pos('/v1/email/check',P.Request.URL)>0,'documented email check path');
    C.FFraudKey:='';
    PlanDenied(H,'ffraud','ip','127.0.0.1','provider lookup rejects local IP');
    PlanDenied(H,'ffraud','ip','1.1.1.1/24','bulk CIDR not accepted as an IP');
    P:=H.Plan('rlive','search','Acme & Co',5);
    Check(P.Request.URL='https://api.ransomware.live/v2/searchvictims/Acme%20%26%20Co','RLV v2 path encoding');
    Check(P.GapMS=60000,'RLV v2 minimum endpoint cooldown');
    C.RLiveMode:='pro'; C.RLiveKey:='test_rlive'; P:=H.Plan('rlive','search','Acme',5);
    Check((P.Request.URL='https://api-pro.ransomware.live/victims/search?q=Acme') and
      (P.Request.Headers[0]='X-API-KEY: test_rlive'),'RLV Pro route and header'); C.RLiveMode:='v2';
    P:=H.Plan('rlook','search','Acme',5); Check(P.Request.URL='https://www.ransomlook.io/api/search?q=Acme','RansomLook Swagger q parameter (not outdated query example)');
    P:=H.Plan('rlook','recent','',3); Check(P.Request.URL='https://www.ransomlook.io/api/recent/3','RansomLook recent count endpoint (not days)');
    PlanDenied(H,'shodan','host','1.1.1.1','unconfigured Shodan disabled');
    C.ShodanKey:='test-shodan'; PlanDenied(H,'shodan','search','org:Acme','credit-using search requires opt-in');
    C.SearchEnabled:=True; P:=H.Plan('shodan','search','org:"Acme" & key=bad',5);
    Check(Pos('org%3A%22Acme%22%20%26%20key%3Dbad',P.Request.URL)>0,'Shodan queries URL-encoded');
    PlanDenied(H,'shodan','scan','1.1.1.1','no plan for active Shodan scan');
    M.Body:='[{"victim":"Acme","group":"sample","discovered":"2026-01-01","claim_url":"HIDDEN_ONION","infostealer":{"password":"HIDDEN_PASSWORD"}}]';
    R:=H.Fetch('rlive','recent','',5);
    try S:=RenderReply('rlive','recent','',R,5); Check(not R.Cached,'first response fresh');
      Check((Pos('Acme',S)>0) and (Pos('HIDDEN_',S)=0),'victim metadata allowlist excludes leak links/infostealer details');
    finally R.JSON.Free; end;
    R:=H.Fetch('rlive','recent','',1);
    try Check(R.Cached and (M.Count=1),'cache shared across local display limits'); finally R.JSON.Free; end;
    M.Body:='{"posts":[{"post_title":"Example Corp","group_name":"sample"}],"leaks":[{"password":"SECRET_LEAK"}]}';
    R:=H.Fetch('rlook','search','Example',5);
    try S:=RenderReply('rlook','search','Example',R,5);
      Check((Pos('Example Corp',S)>0) and (Pos('SECRET_LEAK',S)=0),'cross-entity search only renders post metadata');
    finally R.JSON.Free; end;
    Blocked:=False;
    try R:=H.Fetch('rlook','search','Other',5); R.JSON.Free; except on E:ESafeError do Blocked:=True; end;
    Check(Blocked and (M.Count=2),'provider cooldown checked before network');
    M.Body:='{"fraud_score":0,"risk":"none","vpn":false}';
    R:=H.Fetch('ffraud','ip','1.1.1.1');
    try S:=RenderReply('ffraud','ip','1.1.1.1',R,5); Check(Pos('0/100',S)>0,'zero fraud score not treated as missing'); finally R.JSON.Free; end;
  finally H.Free; M.Free; C.Free; end;
  C:=TBotConfig.FromJSON(BaseConfig); M:=TMock.Create; M.Status:=429;
  M.Headers:='Retry-After: 180'+#13#10; H:=TProviderHub.Create(C,M);
  try
    Blocked:=False;
    try R:=H.Fetch('rlook','recent','',5); R.JSON.Free; except on E:ESafeError do Blocked:=Pos('180',E.Message)>0; end;
    Check(Blocked,'provider Retry-After surfaced safely');
    Blocked:=False;
    try R:=H.Fetch('rlook','recent','',5); R.JSON.Free; except on E:ESafeError do Blocked:=True; end;
    Check(Blocked and (M.Count=1),'no immediate retry after provider 429');
  finally H.Free; M.Free; C.Free; end;
end;
procedure Limits;
var S:TBotState; I:Integer;
begin
  S:=TBotState.Create;
  try
    Check(S.Admit('id','user')=adAccepted,'first job admitted');
    Check((S.Admit('id','user')=adDuplicate) and (S.Jobs=1),'duplicate interaction never starts second job'); S.Finish;
    for I:=2 to 5 do begin Check(S.Admit('id'+IntToStr(I),'user')=adAccepted,'within user allowance'); S.Finish; end;
    Check(S.Admit('id6','user')=adRateLimited,'sixth command in a minute rejected');
    for I:=1 to 4 do Check(S.Admit('busy'+IntToStr(I),'u'+IntToStr(I))=adAccepted,'worker slot available');
    Check(S.Admit('busy5','u5')=adBusy,'fifth simultaneous job rejected');
    S.Cancel('busy1'); Check(S.Admit('busy1','u1')=adAccepted,'cancelled unacknowledged job can be retried');
    Check(S.TakeTarget(Guild,'edge'),'first target check admitted');
    Check(not S.TakeTarget(Guild,'edge'),'target cooldown prevents repeated checks');
  finally S.Free; end;
end;
begin
  InitCrypto;
  try Basics; Signatures; ConfigAndScope; Commands; Providers; Limits;
  except on E:Exception do begin Inc(Failed); WriteLn('UNEXPECTED ',E.ClassName,': ',E.Message); end; end;
  WriteLn('RESULT ',Passed,' passed; ',Failed,' failed.');
  if Failed>0 then ExitCode:=1;
end.
