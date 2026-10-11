unit sp_providers;
{$mode objfpc}{$H+}
interface
uses SysUtils, Classes, SyncObjs, fpjson, sp_common, sp_config, sp_http;
type
  TApiPlan = record
    Request: THttpRequest;
    CacheKey, Bucket, Source: string;
    GapMS: QWord;
  end;
  TApiReply = record
    JSON: TJSONData; {caller owns JSON}
    Source, FetchedUTC: string;
    Cached: Boolean;
  end;
  TProviderHub = class
  private
    FConfig:TBotConfig;
    FTransport:TTransport; {borrowed}
    FLock:TCriticalSection;
    FCache,FGates:TStringList;
    FCacheBytes:SizeInt;
    procedure PruneCache;
    procedure DropCache(Index:Integer);
  public
    constructor Create(C:TBotConfig; Transport:TTransport);
    destructor Destroy; override;
    function Plan(const Service,Action,Arg:string; Limit:Integer):TApiPlan;
    function Fetch(const Service,Action,Arg:string; Limit:Integer=5):TApiReply;
  end;
function ReplyMeta(const R:TApiReply):string;
function ParseJSONSafe(const Body:string):TJSONData;
implementation
uses jsonparser;
type
  TCacheEntry=class
    Body,Stamp:string;
    UntilTick:QWord;
  end;
  TGate=class
    UntilTick:QWord;
  end;
function ParseJSONSafe(const Body:string):TJSONData;
var I,Depth:Integer; InString,Escaped:Boolean; C:Char;
begin
  Require(Length(Body)<=4*1024*1024,'JSON exceeds the size limit.');
  Depth:=0; InString:=False; Escaped:=False;
  for I:=1 to Length(Body) do begin
    C:=Body[I];
    if InString then begin
      if Escaped then Escaped:=False
      else if C='\' then Escaped:=True
      else if C='"' then InString:=False;
    end else begin
      if C='"' then InString:=True
      else if C in ['{','['] then begin Inc(Depth); Require(Depth<=48,'JSON nesting exceeds the limit.'); end
      else if C in ['}',']'] then Dec(Depth);
    end;
  end;
  try Result:=GetJSON(Body);
  except raise ESafeError.Create('Provider/request returned invalid JSON.'); end;
end;
function ReplyMeta(const R:TApiReply):string;
begin
  Result:=R.Source+' | fetched '+R.FetchedUTC;
  if R.Cached then Result+=' | cached (5 min TTL)';
end;
constructor TProviderHub.Create(C:TBotConfig; Transport:TTransport);
begin
  inherited Create; FConfig:=C; FTransport:=Transport;
  FLock:=TCriticalSection.Create; FCache:=TStringList.Create; FGates:=TStringList.Create;
  FCache.CaseSensitive:=True; FGates.CaseSensitive:=True;
end;
destructor TProviderHub.Destroy;
var I:Integer;
begin
  for I:=0 to FCache.Count-1 do FCache.Objects[I].Free;
  for I:=0 to FGates.Count-1 do FGates.Objects[I].Free;
  FCache.Free; FGates.Free; FLock.Free; inherited Destroy;
end;
procedure TProviderHub.DropCache(Index:Integer);
begin
  Dec(FCacheBytes,Length(TCacheEntry(FCache.Objects[Index]).Body));
  FCache.Objects[Index].Free; FCache.Delete(Index);
end;
procedure TProviderHub.PruneCache;
var I:Integer;
begin
  for I:=FCache.Count-1 downto 0 do
    if TCacheEntry(FCache.Objects[I]).UntilTick<=GetTickCount64 then DropCache(I);
end;
function TProviderHub.Plan(const Service,Action,Arg:string; Limit:Integer):TApiPlan;
var Base,Route,S:string; J:TJSONObject; P,I:Integer;
  procedure JSONBody(const Name,Val:string);
  begin
    J:=TJSONObject.Create([Name,Val]);
    try Result.Request.Body:=J.AsJSON; finally J.Free; end;
    Result.Request.Method:='POST';
  end;
  procedure Auth(const Header,Key:string);
  begin SetLength(Result.Request.Headers,1); Result.Request.Headers[0]:=Header+': '+Key; end;
  procedure PublicIP;
  begin Require(IsPublicIP(Arg),'Enter one canonical public IPv4/IPv6 address (not a URL or CIDR).'); end;
  procedure SearchText;
  var K:Integer;
  begin
    Require((Length(Arg)>=2) and (Length(Arg)<=200),'Search text must be 2-200 bytes.');
    for K:=1 to Length(Arg) do Require(Ord(Arg[K])>=32,'Search text cannot contain controls.');
  end;
begin
  Result:=Default(TApiPlan);
  Require((Limit>=1) and (Limit<=10),'Result limit must be 1-10.');
  Result.Request.Method:='GET'; Result.Request.MaxBytes:=4*1024*1024;
  Result.CacheKey:=Service+'/'+Action+'/'+Arg+'/'+IntToStr(Limit);
  Result.Bucket:=Service; Result.GapMS:=1000;
  Route:=''; Base:='';
  if Service='ffraud' then begin
    Base:='https://api.ffraud.com'; Result.Source:='FFraud';
    if Action='ip' then begin
      PublicIP;
      if FConfig.FFraudKey='' then Route:='/public/ip/'+URLPart(Arg)
      else begin Route:='/v1/ip/check'; JSONBody('ip',Arg); Auth('X-API-Key',FConfig.FFraudKey); end;
    end else if Action='email' then begin
      P:=Pos('@',Arg);
      Require((P>=2) and (P<=65) and (Length(Arg)<=254) and IsDomain(Copy(Arg,P+1,Length(Arg))),
        'Enter a conventional email address (ASCII/punycode domain).');
      for I:=1 to P-1 do Require(Arg[I] in ['a'..'z','A'..'Z','0'..'9','.','_','+','-'],
        'Quoted/internationalized mailbox names are not supported.');
      Route:='/public/email/check';
      if FConfig.FFraudKey<>'' then begin Route:='/v1/email/check'; Auth('X-API-Key',FConfig.FFraudKey); end;
      JSONBody('email',Arg);
    end;
  end else if Service='rlive' then begin
    Result.Source:='Ransomware.live '+FConfig.RLiveMode;
    if FConfig.RLiveMode='pro' then begin
      Require(FConfig.RLiveKey<>'','Ransomware.live Pro key is not configured.');
      Base:='https://api-pro.ransomware.live'; Auth('X-API-KEY',FConfig.RLiveKey);
      case Action of
        'recent':Route:='/victims/recent';
        'search':begin SearchText; Route:='/victims/search?q='+URLPart(Arg); end;
        'groups':Route:='/groups';
        'group':begin SearchText; Route:='/groups/'+URLPart(LowerCase(Arg)); end;
      end;
    end else begin
      Base:='https://api.ransomware.live/v2'; Result.GapMS:=60000;
      Result.Bucket:='rlive-v2/'+Action; {conservative per endpoint, across all arguments}
      case Action of
        'recent':Route:='/recentvictims';
        'search':begin SearchText; Route:='/searchvictims/'+URLPart(Arg); end;
        'groups':Route:='/groups';
        'group':begin SearchText; Route:='/group/'+URLPart(LowerCase(Arg)); end;
      end;
    end;
    {Limit is local; share the same cached provider document between display sizes.}
    Result.CacheKey:=Service+'/'+Action+'/'+Arg;
  end else if Service='rlook' then begin
    Base:='https://www.ransomlook.io/api'; Result.Source:='RansomLook';
    case Action of
      'recent':Route:='/recent/'+IntToStr(Limit);
      'search':begin SearchText; Route:='/search?q='+URLPart(Arg); end;
      'groups':Route:='/groups';
      'group':begin SearchText; Route:='/group/'+URLPart(LowerCase(Arg)); end;
      'stats':Route:='/stats';
    end;
    if Action<>'recent' then Result.CacheKey:=Service+'/'+Action+'/'+Arg;
  end else if Service='shodan' then begin
    Require(FConfig.ShodanKey<>'','Shodan is disabled: configure SHODAN_API_KEY.');
    Base:='https://api.shodan.io'; Result.Source:='Shodan (passive index)';
    S:='key='+URLPart(FConfig.ShodanKey);
    case Action of
      'host':begin PublicIP; Route:='/shodan/host/'+URLPart(Arg)+'?minify=true&'+S; end;
      'count':begin SearchText; Route:='/shodan/host/count?query='+URLPart(Arg)+'&facets=country:3&'+S; end;
      'search':begin
        Require(FConfig.SearchEnabled,'Search is disabled; enable SHODAN_SEARCH_ENABLED to permit query-credit usage.');
        SearchText; Route:='/shodan/host/search?query='+URLPart(Arg)+'&page=1&minify=true&'+S;
      end;
      'dns':begin Require(IsDomain(Arg),'Enter a plain domain, not a URL.'); Route:='/dns/resolve?hostnames='+URLPart(LowerCase(Arg))+'&'+S; end;
      'account':Route:='/api-info?'+S;
    end;
    Result.CacheKey:=Service+'/'+Action+'/'+Arg;
  end else if Service='dns' then begin
    Require(IsDomain(Arg),'Invalid scoped DNS name.');
    Require((Action='A') or (Action='AAAA') or (Action='CAA'),'Unsupported DNS record type.');
    Base:='https://cloudflare-dns.com'; Route:='/dns-query?name='+URLPart(Arg)+'&type='+Action;
    Result.Source:='Cloudflare DNS-over-HTTPS'; Result.Bucket:='dns/'+Action;
    SetLength(Result.Request.Headers,1); Result.Request.Headers[0]:='Accept: application/dns-json';
  end;
  Require((Base<>'') and (Route<>''),'Unknown provider operation.');
  Result.Request.URL:=Base+Route;
end;
function TProviderHub.Fetch(const Service,Action,Arg:string; Limit:Integer):TApiReply;
var P:TApiPlan; E:TCacheEntry; G:TGate; H:THttpResponse; I,WaitS:Integer;
    Raw,Stamp:string; Tick:QWord;
begin
  Result:=Default(TApiReply); P:=Plan(Service,Action,Arg,Limit); Result.Source:=P.Source;
  Raw:=''; Stamp:='';
  FLock.Enter;
  try
    PruneCache; Tick:=GetTickCount64;
    I:=FCache.IndexOf(P.CacheKey);
    if I>=0 then begin
      E:=TCacheEntry(FCache.Objects[I]); Raw:=E.Body; Stamp:=E.Stamp; Result.Cached:=True;
    end else begin
      I:=FGates.IndexOf(P.Bucket);
      if I<0 then I:=FGates.AddObject(P.Bucket,TGate.Create);
      G:=TGate(FGates.Objects[I]);
      if G.UntilTick>Tick then begin
        WaitS:=(G.UntilTick-Tick+999) div 1000;
        raise ESafeError.CreateFmt('%s cooldown: retry in about %d seconds.',[P.Source,WaitS]);
      end;
      G.UntilTick:=Tick+P.GapMS;
    end;
  finally FLock.Leave; end;
  if Result.Cached then begin Result.JSON:=ParseJSONSafe(Raw); Result.FetchedUTC:=Stamp; Exit; end;
  H:=FTransport.Send(P.Request);
  if H.Status=429 then begin
    WaitS:=StrToIntDef(HeaderValue(H.Headers,'Retry-After'),60);
    if WaitS<1 then WaitS:=1; if WaitS>3600 then WaitS:=3600;
    FLock.Enter;
    try
      G:=TGate(FGates.Objects[FGates.IndexOf(P.Bucket)]);
      if G.UntilTick<GetTickCount64+QWord(WaitS)*1000 then G.UntilTick:=GetTickCount64+QWord(WaitS)*1000;
    finally FLock.Leave; end;
    raise ESafeError.CreateFmt('%s rate limited this request. Wait about %d seconds.',[P.Source,WaitS]);
  end;
  case H.Status of
    401,403:raise ESafeError.Create(P.Source+' denied the request. Check the API key/plan.');
    404:raise ESafeError.Create(P.Source+' returned no record (HTTP 404).');
  end;
  Require((H.Status>=200) and (H.Status<300),P.Source+' returned HTTP '+IntToStr(H.Status)+'. No provider error body was exposed.');
  Result.JSON:=ParseJSONSafe(H.Body); Result.FetchedUTC:=UTCStamp;
  FLock.Enter;
  try
    if Length(H.Body)<=2*1024*1024 then begin
      while (FCache.Count>=64) or ((FCacheBytes+Length(H.Body))>8*1024*1024) do DropCache(0);
      I:=FCache.IndexOf(P.CacheKey); if I>=0 then DropCache(I);
      E:=TCacheEntry.Create; E.Body:=H.Body; E.Stamp:=Result.FetchedUTC; E.UntilTick:=GetTickCount64+300000;
      FCache.AddObject(P.CacheKey,E); Inc(FCacheBytes,Length(E.Body));
    end;
  finally FLock.Leave; end;
end;
end.
