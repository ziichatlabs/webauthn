import 'dart:convert';
import 'dart:typed_data';

import '../db/credential.dart';

class PublicKeyCredentialSource {
  final String rpId;
  final Uint8List userHandle;
  final Uint8List id;
  int signCount;
  final int alg;
  final String otherUI;

  PublicKeyCredentialSource({
    required this.rpId,
    required this.userHandle,
    required this.id,
    this.signCount = 0,
    this.alg = -7,
    required this.otherUI,
  });

  // Convert object to JSON
  Map<String, dynamic> toJson() {
    return {
      'rpId': rpId,
      'userHandle': base64Encode(userHandle), // Encode binary data to base64
      'id': base64Encode(id), // Encode binary data to base64
      'signCount': signCount,
      'alg': alg,
      'otherUI': otherUI,
    };
  }

  // Create object from JSON
  factory PublicKeyCredentialSource.fromJson(Map<String, dynamic> json) {
    return PublicKeyCredentialSource(
      rpId: json['rpId'] as String,
      userHandle: base64Decode(json['userHandle'] as String),
      id: base64Decode(json['id'] as String),
      signCount: json['signCount'] as int? ?? 0,
      alg: json['alg'] as int? ?? -7,
      otherUI: json['otherUI'] as String? ?? '',
    );
  }

  Credential toCredential() {
    return Credential(
      rpId: rpId,
      username: otherUI,
      userHandle: userHandle,
      keyPairAlias: Credential.genKeyPairAlias(),
      keyId: id,
      keyUseCounter: signCount,
      authRequired: true,
      strongboxRequired: true,
    );
  }

  String get keyLabel {
    final userHex =
        userHandle.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
    return '$rpId/$userHex';
  }
}
