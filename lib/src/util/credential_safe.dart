import 'dart:convert';
import 'dart:typed_data';

import 'package:byte_extensions/byte_extensions.dart';
import 'package:cbor/cbor.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

import '../db/credential.dart';
import '../exceptions.dart';
import './webauthn_cryptography.dart';

class CredentialSafe {
  CredentialSafe({
    this.authenticationRequired = true,
    this.strongboxRequired = true,
    FlutterSecureStorage? storageInst,
    LocalAuthentication? localAuth,
  })  : _storage = storageInst ?? const FlutterSecureStorage(),
        _localAuth = localAuth ?? LocalAuthentication();

  final bool authenticationRequired;
  final bool strongboxRequired;
  final FlutterSecureStorage _storage;
  final LocalAuthentication _localAuth;

  Future<bool> supportsUserVerification() async {
    if (authenticationRequired) {
      return await _localAuth.isDeviceSupported();
    }
    return false;
  }

  Future<KeyPair> _generateNewES256KeyPair(String alias) async {
    final keypair = KeyPair.generateEc(WebauthnCryptography.keyCurve);
    final pk = keypair.privateKey as EcPrivateKey;
    final pub = keypair.publicKey as EcPublicKey;

    final encoded = _encodeKeypair(pk, pub);
    await _storage.write(key: alias, value: base64.encode(encoded));

    return keypair;
  }

  Uint8List _encodeKeypair(EcPrivateKey pk, EcPublicKey pub) {
    return Uint8List.fromList(
      cbor.encode(
        CborList([
          CborBigInt(pk.eccPrivateKey),
          CborBigInt(pub.xCoordinate),
          CborBigInt(pub.yCoordinate),
        ]),
      ),
    );
  }

  Future<KeyPair?> _loadKeyPairFromAlias(String alias) async {
    final encoded = await _storage.read(key: alias);
    if (encoded != null) {
      final cborList = cbor.decode(base64.decode(encoded)) as CborList;
      final pk = EcPrivateKey(
        eccPrivateKey: cborList[0].toObject() as BigInt,
        curve: WebauthnCryptography.keyCurve,
      );
      final pub = EcPublicKey(
        xCoordinate: cborList[1].toObject() as BigInt,
        yCoordinate: cborList[2].toObject() as BigInt,
        curve: WebauthnCryptography.keyCurve,
      );
      return KeyPair(publicKey: pub, privateKey: pk);
    }
    return null;
  }

  Future<Credential> generateCredential(
    String rpEntityId,
    Uint8List userHandle,
    String username, [
    bool? requireUserVerification,
  ]) async {
    final credential = Credential.forKey(
      rpEntityId,
      userHandle,
      username,
      requireUserVerification ?? authenticationRequired,
      strongboxRequired,
    );

    return credential;
  }

  Future<void> _saveCredentialMetadata(Credential credential) async {
    final metadata = {
      'rpId': credential.rpId,
      'username': credential.username,
      'userHandle': base64.encode(credential.userHandle),
      'keyId': base64.encode(credential.keyId),
      'keyUseCounter': credential.keyUseCounter,
      'authRequired': credential.authRequired,
      'strongboxRequired': credential.strongboxRequired,
    };

    await _storage.write(
      key: credential.keyPairAlias + '_metadata',
      value: jsonEncode(metadata),
    );
  }

  Future<void> deleteCredential(Credential credential) async {
    await _storage.delete(key: credential.keyPairAlias);
    await _storage.delete(key: credential.keyPairAlias + '_metadata');
  }

  Future<List<Credential>> getKeysForEntity(String rpEntityId) async {
    final allKeys = await _storage.readAll();
    final credentials = <Credential>[];

    for (var entry
        in allKeys.entries.where((e) => e.key.contains('_metadata'))) {
      final metadata = jsonDecode(entry.value);
      if (metadata['rpId'] == rpEntityId) {
        credentials.add(Credential.fromMetadata(metadata, entry.key));
      }
    }

    return credentials;
  }

  Future<Credential?> getCredentialBySourceKey(Uint8List keyId) async {
    final allKeys = await _storage.readAll();
    final keyIdBase64 = base64.encode(keyId);

    for (var entry
        in allKeys.entries.where((e) => e.key.contains('_metadata'))) {
      final metadata = jsonDecode(entry.value);
      if (metadata['keyId'] == keyIdBase64) {
        return Credential.fromMetadata(metadata, entry.key);
      }
    }

    return null;
  }

  Future<KeyPair?> getKeyPairByAlias(String alias) async {
    return _loadKeyPairFromAlias(alias);
  }

  Future<int> incrementCredentialUseCounter(Credential credential) async {
    final updatedCredential =
        await _loadCredentialFromAlias(credential.keyPairAlias);
    if (updatedCredential != null) {
      updatedCredential.copyWith(keyUseCounter: credential.keyUseCounter + 1);
      await _saveCredentialMetadata(updatedCredential);
      return updatedCredential.keyUseCounter;
    }
    return 0;
  }

  Future<Credential?> _loadCredentialFromAlias(String alias) async {
    final metadataString = await _storage.read(key: alias + '_metadata');
    if (metadataString != null) {
      final metadata = jsonDecode(metadataString);
      return Credential.fromMetadata(metadata, alias);
    }
    return null;
  }

  Future<bool?> keyRequiresVerification(String alias) async {
    final metadataString = await _storage.read(key: alias + '_metadata');
    if (metadataString != null) {
      final metadata = jsonDecode(metadataString);
      return metadata['authRequired'];
    }
    return null;
  }

  static Uint8List coseEncodePublicKey(PublicKey publicKey) {
    if (publicKey is! EcPublicKey) {
      throw InvalidArgumentException('PublicKey must be an EcPublicKey');
    }

    final xCoord = publicKey.xCoordinate.asBytes(maxBytes: 32);
    final yCoord = publicKey.yCoordinate.asBytes(maxBytes: 32);

    final encoded = cbor.encode(
      CborMap({
        const CborSmallInt(1): const CborSmallInt(2),
        const CborSmallInt(3):
            const CborSmallInt(WebauthnCryptography.signingAlgoId),
        const CborSmallInt(-1):
            const CborSmallInt(WebauthnCryptography.keyCurveId),
        const CborSmallInt(-2): CborBytes(xCoord),
        const CborSmallInt(-3): CborBytes(yCoord),
      }),
    );

    return Uint8List.fromList(encoded);
  }

  Uint8List _hexStringToUint8List(String hex) {
    return Uint8List.fromList(
      List.generate(
        hex.length ~/ 2,
        (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
      ),
    );
  }
}
