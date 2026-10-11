unit sp_http;
{$mode objfpc}{$H+}{$packrecords c}
interface
uses SysUtils, Classes, ctypes, sp_common;
type
  THttpRequest = record
    Method, URL, Body: string;
    Headers: TStringArray;
    PinnedHost, PinnedIPv4: string;
    PinnedPort: Word;
    HeadOnly, CertificateInfo: Boolean;
    MaxBytes: Integer;
  end;
  THttpResponse = record
    Status: Integer;
    Body, Headers, PrimaryIP, Certificate: string;
    Seconds: Double;
  end;
  TTransport = class
    function Send(const R: THttpRequest): THttpResponse; virtual; abstract;
  end;
  TCurlTransport = class(TTransport)
    function Send(const R: THttpRequest): THttpResponse; override;
  end;
function HeaderValue(const Headers, Name: string): string;
procedure InitHTTP;
procedure DoneHTTP;
implementation
const
  CURLOPT_URL=10002; CURLOPT_PROXY=10004; CURLOPT_WRITEDATA=10001;
  CURLOPT_WRITEFUNCTION=20011; CURLOPT_HEADERDATA=10029; CURLOPT_HEADERFUNCTION=20079;
  CURLOPT_USERAGENT=10018; CURLOPT_HTTPHEADER=10023; CURLOPT_CUSTOMREQUEST=10036;
  CURLOPT_POSTFIELDS=10015; CURLOPT_POSTFIELDSIZE=60; CURLOPT_NOBODY=44;
  CURLOPT_FOLLOWLOCATION=52; CURLOPT_SSL_VERIFYPEER=64; CURLOPT_SSL_VERIFYHOST=81;
  CURLOPT_NOSIGNAL=99; CURLOPT_CONNECTTIMEOUT_MS=156; CURLOPT_TIMEOUT_MS=155;
  CURLOPT_CERTINFO=172; CURLOPT_RESOLVE=10203; CURLOPT_PROTOCOLS_STR=10318;
  CURLINFO_RESPONSE_CODE=$200002; CURLINFO_PRIMARY_IP=$100020;
  CURLINFO_TOTAL_TIME=$300003; CURLINFO_CERTINFO=$400022;
type
  PCurlSList=^TCurlSList;
  TCurlSList=record Data:PChar; Next:PCurlSList; end;
  PPCurlSList=^PCurlSList;
  PCertInfo=^TCertInfo;
  TCertInfo=record Count:cint; Lists:PPCurlSList; end;
  PContext=^TContext;
  TContext=record Body,Headers:string; MaxBytes:SizeUInt; TooLarge:Boolean; end;
function curl_global_init(Flags: clong): cint; cdecl; external 'curl';
procedure curl_global_cleanup; cdecl; external 'curl';
function curl_easy_init: Pointer; cdecl; external 'curl';
procedure curl_easy_cleanup(H: Pointer); cdecl; external 'curl';
function curl_easy_setopt(H: Pointer; Opt: cint): cint; cdecl; varargs; external 'curl';
function curl_easy_getinfo(H: Pointer; Info: cint): cint; cdecl; varargs; external 'curl';
function curl_easy_perform(H: Pointer): cint; cdecl; external 'curl';
function curl_slist_append(L: PCurlSList; S: PChar): PCurlSList; cdecl; external 'curl';
procedure curl_slist_free_all(L: PCurlSList); cdecl; external 'curl';
procedure InitHTTP;
begin Require(curl_global_init(3)=0,'Unable to initialize TLS/HTTP transport.'); end;
procedure DoneHTTP;
begin curl_global_cleanup; end;
function BodyCB(P: Pointer; Size,N: SizeUInt; User: Pointer): SizeUInt; cdecl;
var C:PContext; Bytes:SizeUInt; S:string;
begin
  Result := 0;
  try
    C := PContext(User); Bytes := Size*N;
    if Bytes > C^.MaxBytes-SizeUInt(Length(C^.Body)) then begin C^.TooLarge:=True; Exit; end;
    SetString(S,PChar(P),Bytes); C^.Body += S; Result:=Bytes;
  except Result:=0; end;
end;
function HeaderCB(P: Pointer; Size,N: SizeUInt; User: Pointer): SizeUInt; cdecl;
var C:PContext; Bytes:SizeUInt; S:string;
begin
  Result:=0;
  try
    C:=PContext(User); Bytes:=Size*N;
    if Bytes > 65536-SizeUInt(Length(C^.Headers)) then begin C^.TooLarge:=True; Exit; end;
    SetString(S,PChar(P),Bytes); C^.Headers += S; Result:=Bytes;
  except Result:=0; end;
end;
function HeaderValue(const Headers, Name: string): string;
var L:TStringList; I,P:Integer;
begin
  Result:=''; L:=TStringList.Create;
  try
    L.Text:=Headers;
    for I:=0 to L.Count-1 do begin
      P:=Pos(':',L[I]);
      if (P>0) and SameText(Copy(L[I],1,P-1),Name) then Result:=Trim(Copy(L[I],P+1,Length(L[I])));
    end;
  finally L.Free; end;
end;
function TCurlTransport.Send(const R: THttpRequest): THttpResponse;
var H:Pointer; C:TContext; L,ResolveList,Node:PCurlSList; CI:PCertInfo;
    Code:cint; Status:clong; IP:PChar; Entry,S:string; I:Integer;
  procedure SetLong(Opt:cint; V:clong);
  begin Require(curl_easy_setopt(H,Opt,V)=0,'Unsupported HTTP transport option.'); end;
  procedure SetStr(Opt:cint; const V:string);
  begin Require(curl_easy_setopt(H,Opt,PChar(V))=0,'Unsupported HTTP transport option.'); end;
begin
  Result:=Default(THttpResponse);
  Require(Copy(R.URL,1,8)='https://','Only HTTPS provider/HTTP-check requests are allowed.');
  H:=curl_easy_init; Require(H<>nil,'HTTP initialization failed.');
  C:=Default(TContext); C.MaxBytes:=4*1024*1024;
  if R.MaxBytes>0 then C.MaxBytes:=R.MaxBytes;
  L:=nil; ResolveList:=nil;
  try
    SetStr(CURLOPT_URL,R.URL); SetStr(CURLOPT_PROXY,'');
    SetStr(CURLOPT_PROTOCOLS_STR,'https');
    SetStr(CURLOPT_USERAGENT,'SentinelPascal/1.0 (defensive intelligence)');
    SetLong(CURLOPT_NOSIGNAL,1); SetLong(CURLOPT_FOLLOWLOCATION,0);
    SetLong(CURLOPT_SSL_VERIFYPEER,1); SetLong(CURLOPT_SSL_VERIFYHOST,2);
    SetLong(CURLOPT_CONNECTTIMEOUT_MS,4000); SetLong(CURLOPT_TIMEOUT_MS,12000);
    Require(curl_easy_setopt(H,CURLOPT_WRITEFUNCTION,@BodyCB)=0,'HTTP callback setup failed.');
    Require(curl_easy_setopt(H,CURLOPT_WRITEDATA,@C)=0,'HTTP callback setup failed.');
    Require(curl_easy_setopt(H,CURLOPT_HEADERFUNCTION,@HeaderCB)=0,'HTTP callback setup failed.');
    Require(curl_easy_setopt(H,CURLOPT_HEADERDATA,@C)=0,'HTTP callback setup failed.');
    S:='application/json';
    for I:=0 to High(R.Headers) do
      if SameText(Copy(R.Headers[I],1,7),'Accept:') then S:='';
    if S<>'' then L:=curl_slist_append(L,'Accept: application/json');
    L:=curl_slist_append(L,'Content-Type: application/json');
    for I:=0 to High(R.Headers) do begin
      Require((Pos(#13,R.Headers[I])=0) and (Pos(#10,R.Headers[I])=0),'Invalid request header.');
      L:=curl_slist_append(L,PChar(R.Headers[I]));
    end;
    Require(curl_easy_setopt(H,CURLOPT_HTTPHEADER,L)=0,'HTTP header setup failed.');
    if R.Method<>'' then SetStr(CURLOPT_CUSTOMREQUEST,R.Method);
    if R.Body<>'' then begin
      SetLong(CURLOPT_POSTFIELDSIZE,Length(R.Body));
      Require(curl_easy_setopt(H,CURLOPT_POSTFIELDS,PChar(R.Body))=0,'HTTP body setup failed.');
    end;
    if R.HeadOnly then SetLong(CURLOPT_NOBODY,1);
    if R.CertificateInfo then SetLong(CURLOPT_CERTINFO,1);
    if R.PinnedHost<>'' then begin
      Require(IsDomain(R.PinnedHost) and IsPublicIPv4(R.PinnedIPv4) and (R.PinnedPort=443), 'Invalid pinned HTTPS scope.');
      Require(R.URL='https://'+R.PinnedHost+'/', 'Pinned check URL must exactly match the scope hostname root.');
      Require(R.HeadOnly and (R.Body=''),'Pinned HTTPS checks must be body-free HEAD requests.');
      Entry:=R.PinnedHost+':'+IntToStr(R.PinnedPort)+':'+R.PinnedIPv4;
      ResolveList:=curl_slist_append(nil,PChar(Entry));
      Require(curl_easy_setopt(H,CURLOPT_RESOLVE,ResolveList)=0,'Address pinning failed.');
    end;
    Code:=curl_easy_perform(H);
    Require(not C.TooLarge,'Provider response exceeded the bounded size limit. Narrow the query.');
    if Code<>0 then raise ESafeError.CreateFmt('Connection/TLS check failed (transport code %d). No insecure retry was made.',[Code]);
    Status:=0; IP:=nil;
    curl_easy_getinfo(H,CURLINFO_RESPONSE_CODE,@Status); Result.Status:=Status;
    curl_easy_getinfo(H,CURLINFO_PRIMARY_IP,@IP); if IP<>nil then Result.PrimaryIP:=StrPas(IP);
    curl_easy_getinfo(H,CURLINFO_TOTAL_TIME,@Result.Seconds);
    if R.PinnedHost<>'' then Require(Result.PrimaryIP=R.PinnedIPv4,'Connected IP did not match the authorized scope.');
    Result.Body:=C.Body; Result.Headers:=C.Headers;
    if R.CertificateInfo then begin
      CI:=nil; curl_easy_getinfo(H,CURLINFO_CERTINFO,@CI);
      if (CI<>nil) and (CI^.Count>0) then begin
        Node:=CI^.Lists^; {leaf certificate only; never return PEM blobs}
        while Node<>nil do begin
          S:=StrPas(Node^.Data);
          if (Pos('Subject:',S)=1) or (Pos('Issuer:',S)=1) or
             (Pos('Start date:',S)=1) or (Pos('Expire date:',S)=1) or
             (Pos('Signature Algorithm:',S)=1) then Result.Certificate+=Flat(S,240)+#10;
          Node:=Node^.Next;
        end;
      end;
    end;
  finally
    curl_easy_cleanup(H); curl_slist_free_all(L); curl_slist_free_all(ResolveList);
  end;
end;
end.
