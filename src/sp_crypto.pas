unit sp_crypto;
{$mode objfpc}{$H+}
interface
uses SysUtils, ctypes, sp_common;
procedure InitCrypto;
function VerifyDiscord(const PublicKeyHex, SignatureHex, Timestamp, RawBody: string; CurrentUnix: Int64): Boolean;
implementation
function sodium_init: cint; cdecl; external 'sodium';
function crypto_sign_verify_detached(Sig, Msg: Pointer; MsgLen: QWord; PK: Pointer): cint; cdecl; external 'sodium';
function DecodeHex(const S: string; Dest: Pointer; N: Integer): Boolean;
var I,A,B: Integer;
  function Digit(C: Char): Integer;
  begin
    case C of
      '0'..'9': Result := Ord(C)-Ord('0');
      'a'..'f': Result := Ord(C)-Ord('a')+10;
      'A'..'F': Result := Ord(C)-Ord('A')+10;
      else Result := -1;
    end;
  end;
begin
  Result := False;
  if Length(S) <> N*2 then Exit;
  for I := 0 to N-1 do begin
    A := Digit(S[I*2+1]); B := Digit(S[I*2+2]);
    if (A < 0) or (B < 0) then Exit;
    PByte(Dest)[I] := A*16+B;
  end;
  Result := True;
end;
procedure InitCrypto;
begin Require(sodium_init >= 0,'Unable to initialize signature verification.'); end;
function VerifyDiscord(const PublicKeyHex, SignatureHex, Timestamp, RawBody: string; CurrentUnix: Int64): Boolean;
var PK: array[0..31] of Byte; Sig: array[0..63] of Byte; TS: Int64; Msg: string; C: Char;
begin
  Result := False;
  if (Length(Timestamp) < 1) or (Length(Timestamp) > 12) then Exit;
  for C in Timestamp do if not (C in ['0'..'9']) then Exit;
  if not TryStrToInt64(Timestamp,TS) then Exit;
  if (TS < CurrentUnix-300) or (TS > CurrentUnix+30) then Exit;
  if not DecodeHex(PublicKeyHex,@PK,32) or not DecodeHex(SignatureHex,@Sig,64) then Exit;
  Msg := Timestamp + RawBody;
  Result := crypto_sign_verify_detached(@Sig,PChar(Msg),Length(Msg),@PK)=0;
end;
end.
