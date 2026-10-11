unit sp_common;
{$mode objfpc}{$H+}{$codepage utf8}
interface
uses SysUtils, Classes, DateUtils, fpjson;
type
  ESafeError = class(Exception);
  TStringArray = array of string;
  TPortArray = array of Word;
  TScopeTarget = record
    Alias, GuildID, Hostname, IPv4, Expires: string;
    Ports: TPortArray;
  end;
function UnixNow: Int64;
function UTCStamp: string;
function URLPart(const S: string): string;
function ClipUTF8(const S: string; MaxBytes: Integer): string;
function Flat(const S: string; MaxBytes: Integer = 120): string;
function Field(J: TJSONData; const Name: string): TJSONData;
function TextOf(J: TJSONData; const DefaultValue: string = 'unknown'): string;
function Value(J: TJSONData; const Name: string; const DefaultValue: string = 'unknown'): string;
function FirstValue(J: TJSONData; const Names: array of string): string;
function ArrayText(J: TJSONData; MaxItems: Integer = 12): string;
function IsSnowflake(const S: string): Boolean;
function IsDomain(const S: string): Boolean;
function IsIP(const S: string): Boolean;
function IsPublicIPv4(const S: string): Boolean;
function IsPublicIP(const S: string): Boolean;
function ValidDate(const S: string): Boolean;
function HasPort(const T: TScopeTarget; P: Word): Boolean;
function ReadSmallFile(const Path: string; MaxBytes: Integer = 65536): string;
function MessageData(const S: string): TJSONObject;
function ImmediateResponse(const S: string): string;
procedure Require(Condition: Boolean; const Msg: string);
implementation
uses ctypes;
function inet_pton(AF: cint; Src: PChar; Dst: Pointer): cint; cdecl; external 'c';
function UnixNow: Int64;
begin Result := DateTimeToUnix(Now, False); end;
function UTCStamp: string;
begin Result := FormatDateTime('yyyy"-"mm"-"dd"T"hh":"nn":"ss"Z"', LocalTimeToUniversal(Now)); end;
procedure Require(Condition: Boolean; const Msg: string);
begin if not Condition then raise ESafeError.Create(Msg); end;
function URLPart(const S: string): string;
var I: Integer; C: Char;
begin
  Result := '';
  for I := 1 to Length(S) do begin
    C := S[I];
    if C in ['a'..'z','A'..'Z','0'..'9','-','_','.','~'] then Result += C
    else Result += '%' + IntToHex(Ord(C),2);
  end;
end;
function ClipUTF8(const S: string; MaxBytes: Integer): string;
var N: Integer;
begin
  if Length(S) <= MaxBytes then Exit(S);
  N := MaxBytes;
  while (N > 0) and ((Ord(S[N+1]) and $C0) = $80) do Dec(N);
  Result := Copy(S,1,N);
end;
function Flat(const S: string; MaxBytes: Integer): string;
var I: Integer;
begin
  Result := '';
  for I := 1 to Length(S) do
    if (Ord(S[I]) < 32) or (S[I] = #127) then Result += ' '
    else if S[I] = '`' then Result += ''''
    else Result += S[I];
  Result := ClipUTF8(Trim(Result), MaxBytes);
end;
function Field(J: TJSONData; const Name: string): TJSONData;
begin
  Result := nil;
  if (J <> nil) and (J.JSONType = jtObject) then Result := TJSONObject(J).Find(Name);
end;
function TextOf(J: TJSONData; const DefaultValue: string): string;
begin
  if (J = nil) or (J.JSONType in [jtNull,jtObject,jtArray]) then Exit(DefaultValue);
  Result := Flat(J.AsString);
  if Result = '' then Result := DefaultValue;
end;
function Value(J: TJSONData; const Name: string; const DefaultValue: string): string;
begin Result := TextOf(Field(J,Name),DefaultValue); end;
function FirstValue(J: TJSONData; const Names: array of string): string;
var I: Integer;
begin
  Result := 'unknown';
  for I := Low(Names) to High(Names) do begin
    Result := Value(J,Names[I],'');
    if Result <> '' then Exit;
  end;
  Result := 'unknown';
end;
function ArrayText(J: TJSONData; MaxItems: Integer): string;
var I, N: Integer;
begin
  Result := '';
  if J = nil then Exit('unknown');
  if not (J.JSONType in [jtArray,jtObject]) then Exit(TextOf(J));
  N := J.Count;
  if N > MaxItems then N := MaxItems;
  for I := 0 to N-1 do begin
    if I > 0 then Result += ', ';
    if J.JSONType = jtObject then Result += Flat(TJSONObject(J).Names[I],60)
    else Result += TextOf(J.Items[I]);
  end;
  if J.Count > N then Result += ', ...';
  if Result = '' then Result := '(none returned)';
end;
function IsSnowflake(const S: string): Boolean;
var C: Char;
begin
  Result := False;
  if (Length(S) < 17) or (Length(S) > 20) then Exit;
  for C in S do if not (C in ['0'..'9']) then Exit;
  Result := True;
end;
function IsDomain(const S: string): Boolean;
var I, N, Labels: Integer; C: Char;
begin
  Result := False; N := 0; Labels := 0;
  if (Length(S) < 3) or (Length(S) > 253) then Exit;
  for I := 1 to Length(S) do begin
    C := S[I];
    if C = '.' then begin
      if (N = 0) or (S[I-1] = '-') then Exit;
      N := 0; Inc(Labels);
    end else begin
      if not (C in ['a'..'z','A'..'Z','0'..'9','-']) then Exit;
      if (N = 0) and (C = '-') then Exit;
      Inc(N); if N > 63 then Exit;
    end;
  end;
  if (N = 0) or (S[Length(S)] = '-') or (Labels = 0) or IsIP(S) then Exit;
  Result := True;
end;
function IsIP(const S: string): Boolean;
var B: array[0..15] of Byte;
begin
  Result := (Length(S) <= 45) and (S <> '') and (Pos(#0,S)=0) and
    ((inet_pton(2,PChar(S),@B)=1) or (inet_pton(10,PChar(S),@B)=1));
end;
function IsPublicIPv4(const S: string): Boolean;
var B: array[0..3] of Byte;
begin
  Result := False;
  if (Pos(#0,S)>0) or (Length(S)>15) then Exit;
  if inet_pton(2,PChar(S),@B) <> 1 then Exit;
  if (B[0] = 0) or (B[0] = 10) or (B[0] = 127) or (B[0] >= 224) then Exit;
  if (B[0] = 100) and (B[1] in [64..127]) then Exit;
  if (B[0] = 169) and (B[1] = 254) then Exit;
  if (B[0] = 172) and (B[1] in [16..31]) then Exit;
  if (B[0] = 192) and ((B[1] = 168) or
     ((B[1] = 0) and (B[2] in [0,2])) or ((B[1] = 88) and (B[2] = 99))) then Exit;
  if (B[0] = 198) and ((B[1] in [18,19]) or ((B[1] = 51) and (B[2] = 100))) then Exit;
  if (B[0] = 203) and (B[1] = 0) and (B[2] = 113) then Exit;
  Result := True;
end;
function IsPublicIP(const S: string): Boolean;
var B: array[0..15] of Byte;
begin
  if IsPublicIPv4(S) then Exit(True);
  Result := False;
  if (Pos(#0,S)>0) or (Length(S)>45) then Exit;
  if inet_pton(10,PChar(S),@B) <> 1 then Exit;
  if (B[0] and $E0) <> $20 then Exit; {global unicast only; no mapped IPv4}
  if (B[0] = $20) and (B[1] = $01) and (B[2] = $0D) and (B[3] = $B8) then Exit;
  if (B[0] = $20) and (B[1] = $01) and (B[2] < 2) then Exit; {special-purpose /23}
  if (B[0] = $20) and (B[1] = $02) then Exit; {6to4}
  Result := True;
end;
function ValidDate(const S: string): Boolean;
var Y,M,D: Integer; T: TDateTime;
begin
  Result := False;
  if (Length(S) <> 10) or (S[5] <> '-') or (S[8] <> '-') then Exit;
  if not TryStrToInt(Copy(S,1,4),Y) or not TryStrToInt(Copy(S,6,2),M) or
    not TryStrToInt(Copy(S,9,2),D) then Exit;
  if (Y<1) or (Y>9999) or (M<1) or (M>12) or (D<1) or (D>31) then Exit;
  Result := TryEncodeDate(Y,M,D,T) and (FormatDateTime('yyyy-mm-dd',T) = S);
end;
function HasPort(const T: TScopeTarget; P: Word): Boolean;
var V: Word;
begin Result := False; for V in T.Ports do if V = P then Exit(True); end;
function ReadSmallFile(const Path: string; MaxBytes: Integer): string;
var F: TFileStream;
begin
  F := TFileStream.Create(Path,fmOpenRead or fmShareDenyWrite);
  try
    Require(F.Size <= MaxBytes,'Configuration file exceeds size limit.');
    SetLength(Result,F.Size);
    if F.Size > 0 then F.ReadBuffer(Result[1],F.Size);
  finally F.Free; end;
end;
function MessageData(const S: string): TJSONObject;
var Body: string; I: Integer;
begin
  Body := '';
  for I := 1 to Length(S) do
    if S[I] = '`' then Body += ''''
    else if (Ord(S[I]) >= 32) or (S[I] in [#10,#9]) then Body += S[I];
  if Length(Body) > 1800 then Body := ClipUTF8(Body,1740) + #10 + '[Display truncated; narrow the query.]';
  Result := TJSONObject.Create;
  Result.Add('content','```text' + #10 + Body + #10 + '```');
  Result.Add('allowed_mentions',TJSONObject.Create(['parse',TJSONArray.Create]));
end;
function ImmediateResponse(const S: string): string;
var J,D: TJSONObject;
begin
  D := MessageData(S); D.Add('flags',64);
  J := TJSONObject.Create(['type',4,'data',D]);
  try Result := J.AsJSON; finally J.Free; end;
end;
end.
