import 'dart:convert';
import 'dart:typed_data';

import '../../webauthn.dart';
import '../helpers/base64.dart';
import '../helpers/random.dart';

const _keyPairPrefix = "webauthn-prefix-";

class Credential {
  final String rpId;
  final String username;
  final Uint8List userHandle;
  final String keyPairAlias;
  final Uint8List keyId;
  final int keyUseCounter;
  final bool authRequired;
  final bool strongboxRequired;

  PublicKeyCredentialType get type => PublicKeyCredentialType.publicKey;

  Credential({
    required this.rpId,
    required this.username,
    required this.userHandle,
    required this.keyPairAlias,
    required this.keyId,
    required this.keyUseCounter,
    required this.authRequired,
    required this.strongboxRequired,
  });

  Credential.forKey(
    this.rpId,
    this.userHandle,
    this.username,
    this.authRequired,
    this.strongboxRequired,
  )   : keyId = RandomHelper.nextBytes(32),
        keyPairAlias = genKeyPairAlias(),
        keyUseCounter = 0;

  static String genKeyPairAlias() =>
      _keyPairPrefix + b64e(RandomHelper.nextBytes(32).toList());

  Credential copyWith({
    int? keyUseCounter,
  }) {
    return Credential(
      rpId: this.rpId,
      username: this.username,
      userHandle: this.userHandle,
      keyPairAlias: this.keyPairAlias,
      keyId: this.keyId,
      keyUseCounter: keyUseCounter ?? this.keyUseCounter,
      authRequired: this.authRequired,
      strongboxRequired: this.strongboxRequired,
    );
  }

  factory Credential.fromJson(Map<String, dynamic> json) {
    return Credential(
      rpId: json['rpId'] as String,
      username: json['username'] as String,
      userHandle: base64Decode(json['userHandle'] as String),
      keyPairAlias: json['keyPairAlias'] as String,
      keyId: base64Decode(json['keyId'] as String),
      keyUseCounter: json['keyUseCounter'] as int,
      authRequired: json['authRequired'] as bool,
      strongboxRequired: json['strongboxRequired'] as bool,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'rpId': rpId,
      'username': username,
      'userHandle': userHandle,
      'keyPairAlias': keyPairAlias,
      'keyId': keyId,
      'keyUseCounter': keyUseCounter,
      'authRequired': authRequired,
      'strongboxRequired': strongboxRequired,
    };
  }

  static Credential fromMetadata(Map<String, dynamic> metadata, String alias) {
    return Credential(
      rpId: metadata['rpId'],
      username: metadata['username'],
      userHandle: base64.decode(metadata['userHandle']),
      keyPairAlias: alias.replaceFirst('_metadata', ''),
      keyId: base64.decode(metadata['keyId']),
      keyUseCounter: metadata['keyUseCounter'],
      authRequired: metadata['authRequired'],
      strongboxRequired: metadata['strongboxRequired'],
    );
  }
}
