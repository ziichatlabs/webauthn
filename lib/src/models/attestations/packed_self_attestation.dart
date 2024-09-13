import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';

import '../../enums/attestation_type.dart';
import '../../helpers/base64.dart';
import '../../util/webauthn_cryptography.dart';
import '../attestation.dart';

class PackedSelfAttestation extends Attestation {
  final Uint8List signature;

  PackedSelfAttestation(super.authData, this.signature);

  @override
  String get format {
    return AttestationType.packed.value;
  }

  /// Encode this packed-attestation object as a JSON payload
  /// @see https://www.w3.org/TR/webauthn/#sctn-attestation
  /// @see https://www.w3.org/TR/webauthn/#sctn-packed-attestation
  @override
  String asJSON() {
    return json.encode({
      'authData': b64e(authData),
      'fmt': format,
      'attStmt': {
        'alg': WebauthnCryptography.signingAlgoId,
        'sig': b64e(signature),
      },
    });
  }

  /// Encode this self-attestation object as a CBOR payload
  /// @see https://www.w3.org/TR/webauthn/#sctn-attestation
  /// @see https://www.w3.org/TR/webauthn/#sctn-packed-attestation
  @override
  Uint8List asCBOR() {
    final encoded = cbor.encode(
      CborMap({
        CborString('authData'): CborBytes(authData),
        CborString('fmt'): CborString(format),
        CborString('attStmt'): CborMap({
          CborString('alg'): CborValue(WebauthnCryptography.signingAlgoId),
          CborString('sig'): CborBytes(signature),
        }),
      }),
    );
    return Uint8List.fromList(encoded);
  }
}
