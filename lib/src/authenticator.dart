import 'dart:typed_data';

import 'package:byte_extensions/byte_extensions.dart';
import 'package:crypto_keys/crypto_keys.dart';
import 'package:flutter/foundation.dart';
import 'package:ios_web_authn/ios_web_authn.dart';
import 'package:local_auth/local_auth.dart';
import 'package:logger/logger.dart';

import '../webauthn.dart';
import 'constants.dart' as c;
import 'db/credential.dart';
import 'models/attestations/none_attestation.dart';
import 'models/attestations/packed_self_attestation.dart';

class Authenticator {
  // Allow external references
  static const shaLength = c.shaLength;
  static const authenticationDataLength = c.authenticationDataLength;
  static const minSignatureDataLength = c.minSignatureDataLength;
  static const transports = [AuthenticatorTransports.internal];

  // ignore: constant_identifier_names
  static const ES256_COSE = CredTypePubKeyAlgoPair(
    credType: PublicKeyCredentialType.publicKey,
    pubKeyAlgo: WebauthnCryptography.signingAlgoId,
  );

  /// Create a new instance of the Authenticator.
  ///
  /// Pass `true` for [authenticationRequired] if we want to require authentication
  /// before allowing the key to be accessed and used.
  /// Pass `true` for [strongboxRequired] if we want this key to be managed by the
  /// system strongbox. NOTE: this option is currently ignored because we don't
  /// have access to the system strongbox on all the platforms.
  ///
  /// The default dependencies can be overwritten by passing a mock, or other instance,
  /// to [credentialSafe], [cryptography], or [localAuth]. These should be left as is
  /// except when mocked for unit tests.
  Authenticator(
    this.authenticationRequired,
    bool strongboxRequired, {
    CredentialSafe? credentialSafe,
    WebauthnCryptography? cryptography,
    LocalAuthentication? localAuth,
  })  : _crypto = cryptography ?? const WebauthnCryptography(),
        _credentialSafe = credentialSafe ??
            CredentialSafe(
              authenticationRequired: authenticationRequired,
              strongboxRequired: strongboxRequired,
              localAuth: localAuth,
            ),
        _localAuth = localAuth ?? LocalAuthentication();

  final bool authenticationRequired;
  final CredentialSafe _credentialSafe;
  final WebauthnCryptography _crypto;
  final LocalAuthentication _localAuth;

  final Logger _logger = Logger();

  /// The secure store for our credentials
  @visibleForTesting
  CredentialSafe get credentialSafe {
    return _credentialSafe;
  }

  /// The crypto handling functinality
  @visibleForTesting
  WebauthnCryptography get crytography {
    return _crypto;
  }

  static Future<bool> get isDeviceSupport {
    return LocalAuthentication().isDeviceSupported();
  }

  /// Creates a new instance of the Authenticator required to be used with a given
  /// set of Make Credential [options] and processes the request.
  /// @see [makeCredential] for a description of the arguments
  static Future<Attestation> handleMakeCredential(
    MakeCredentialOptions options, {
    var attestationType = AttestationType.packed,
    var localizationOptions = const AuthenticationLocalizationOptions(),
  }) =>
      Authenticator(options.requireUserVerification, true).makeCredential(
        options,
        attestationType: attestationType,
        localizationOptions: localizationOptions,
      );

  /// Perform the authenticatorMakeCredential operation as defined by the WebAuthn spec
  /// @see https://www.w3.org/TR/webauthn/#sctn-op-make-cred
  ///
  /// The [options] to create the credential should be passed. An [Attestation]
  /// containing the new credential and attestation information is returned.
  Future<Attestation> makeCredential(
    MakeCredentialOptions options, {
    var attestationType = AttestationType.packed,
    var localizationOptions = const AuthenticationLocalizationOptions(),
  }) async {
    // We are going to use a flag rather than explicitly invoking deny-behavior
    // because the spec asks us to pretend everything is normal while asynchronous
    // operations (like asking user consent) happen to ensure privacy guarantees.
    // Flag for whether our credential was in the exclude list
    var excludeFlag = false;

    // Step 1: check if all supplied parameters are syntactically well-formed and of the correct length
    final optionsError = options.hasError();
    if (optionsError != null) {
      _logger.w(
        'Credential options are not syntactically well-formed: $optionsError',
      );
      throw InvalidArgumentException(
        optionsError,
        arguments: {'options': options},
      );
    }

    // Step 2: Check if we support a compatible credential type
    if (!options.credTypesAndPubKeyAlgs.contains(ES256_COSE)) {
      _logger.w('Only ES256 is supported');
      throw InvalidArgumentException(
        'Options must include the ES256 algorithm',
      );
    }

    // Step 3: Check excludeCredentialDescriptorList for existing credentials for this RP
    if (options.excludeCredentialDescriptorList != null) {
      for (var descriptor in options.excludeCredentialDescriptorList!) {
        // If we have a credential identified by this id, flag as excluding
        final existingCreds =
            await _credentialSafe.getCredentialBySourceKey(descriptor.id);
        if (existingCreds != null &&
            existingCreds.rpId == options.rpEntity.id &&
            existingCreds.type == descriptor.type) {
          excludeFlag = true;
          break;
        }
      }
    }

    // Step 4: Check requireResidentKey
    // Our authenticator will store resident keys regardless, so we can disregard the value of this parameter

    // Step 5: Check requireUserVerification
    final requiresUserVerification =
        authenticationRequired || options.requireUserVerification;
    final supportsUserVerifiation =
        await _credentialSafe.supportsUserVerification();
    if (requiresUserVerification && !supportsUserVerifiation) {
      _logger.w('User verification is required but not available');
      throw CredentialCreationException(
        'User verification is required but not available',
      );
    }
    // Step 7: Generate a new credential
    late Credential credentialSource;
    try {
      credentialSource = await _credentialSafe.generateCredential(
        options.rpEntity.id,
        options.userEntity.id,
        options.userEntity.name,
        requiresUserVerification,
      );
    } on Exception catch (e) {
      _logger.w('Couldn\'t generate credential', error: e);
      throw CredentialCreationException('Couldn\'t generate credential');
    }

    final attestation = await _createAttestation(
      attestationType,
      options,
      credentialSource,
    );

    // We finish up Step 3 here by checking excludeFlag at the end (so we've still gotten
    // the user's conset to create a credential etc)
    if (excludeFlag) {
      await _credentialSafe.deleteCredential(credentialSource);
      _logger.w('Credential is excluded by excludeCredentialDescriptorList');
      throw CredentialCreationException(
        'Credential is excluded by excludeCredentialDescriptorList',
      );
    }

    return attestation;
  }

  /// Creates a new instance of the Authenticator required to be used with a given
  /// set of Get Assertion [options] and processes the request.
  /// @see [getAssertion] for a description of the arguments
  static Future<Assertion> handleGetAssertion(
    GetAssertionOptions options, {
    var localizationOptions = const AuthenticationLocalizationOptions(),
  }) =>
      Authenticator(options.requireUserVerification, true).getAssertion(
        options,
        localizationOptions: localizationOptions,
      );

  /// Perform the authenticatorGetAssertion operation as defined by the WebAuthn spec
  /// @see https://www.w3.org/TR/webauthn/#sctn-op-get-assertion
  /// The [options] to get the assertion should be passed. An [Assertion]
  /// containing the selected credential and proofs is returned.
  Future<Assertion> getAssertion(
    GetAssertionOptions options, {
    var localizationOptions = const AuthenticationLocalizationOptions(),
  }) async {
    final optionsError = options.hasError();
    if (optionsError != null) {
      _logger.w(
        'Assertion options are not syntactically well-formed: $optionsError',
      );
      throw InvalidArgumentException(
        optionsError,
        arguments: {'options': options},
      );
    }

    List<Map<String, dynamic>>? allowCredentials =
        options.allowCredentialDescriptorList?.map((descriptor) {
      return {
        "type": "public-key",
        "id": descriptor.id,
        "transports": transports.toString(),
      };
    }).toList();

    final assertion = await IosWebAuthn.getAssertion(
      rpId: options.rpId,
      clientDataHash: options.clientDataHash,
      allowCredentialDescriptorList: allowCredentials!,
      userPresent: options.requireUserPresence,
      requireUserVerification: options.requireUserVerification,
    );

    return Assertion(
      selectedCredentialId: assertion.selectedCredentialId,
      authenticatorData: assertion.authenticatorData,
      signature: assertion.signature,
      selectedCredentialUserHandle: assertion.selectedCredentialUserHandle,
    );
  }

  /// The second half of the makeCredential process
  Future<Attestation> _createAttestation(
    AttestationType attestationType,
    MakeCredentialOptions options,
    Credential credential,
  ) async {
    final attestation = await IosWebAuthn.createAttestation(
      rpId: options.rpEntity.id,
      userHandle: options.userEntity.id,
      username: options.userEntity.name,
      clientDataHash: options.clientDataHash,
      userPresent: true,
      requireUserVerification: true,
    );

    return PackedSelfAttestation(
      attestation.authDataBytes,
      attestation.attStmt.sig,
    );
  }

  /// Constructs an attestedCredentialData object per the WebAuthn Spec
  /// @see https://www.w3.org/TR/webauthn/#sctn-attested-credential-data
  Future<Uint8List> _constructAttestedCredentialData(
      Credential credential) async {
    // | AAGUID | L | credentialId | credentialPublicKey |
    // |   16   | 2 |      32      |          n          |
    // total size: 50+n (for ES256 keypair, n = 77), so total size is 127
    final keyPair =
        await _credentialSafe.getKeyPairByAlias(credential.keyPairAlias);
    if (keyPair == null) {
      throw KeyPairNotFound(credential.keyPairAlias);
    }

    final encodedPublicKey =
        CredentialSafe.coseEncodePublicKey(keyPair.publicKey!);

    final data = BytesBuilder()
      ..add(List.filled(16, 0)) // AAGUID will be 16 bytes of zeros
      ..add(credential.keyId.length.asBytes(type: IntType.int16))
      ..add(credential.keyId) // credentialId
      ..add(encodedPublicKey); // credentialPublicKey
    return data.toBytes();
  }

  /// Constructs an authenticatorData object per the WebAuthn spec
  /// @see https://www.w3.org/TR/webauthn/#sctn-authenticator-data
  Future<Uint8List> _constructAuthenticatorData({
    required Uint8List rpIdHash,
    required Uint8List? credentialData,
    required Uint8List? clientDataHash,
    required int authCounter,
  }) async {
    if (rpIdHash.length != shaLength) {
      throw InvalidArgumentException(
        'rpIdHash must be a $shaLength-byte SHA-256 hash',
        arguments: {'rpIdHash': rpIdHash},
      );
    }
    // | rpIdHash | flags | useCounter | credentialData | extensions
    // |    32    |   1   |     4      |     127 or 0   |   N or 0

    int flags = 0x01; // user present
    if (await _credentialSafe.supportsUserVerification()) {
      flags |= (0x01 << 2); // user verified
    }
    if (credentialData != null && credentialData.isNotEmpty) {
      flags |= (0x01 << 6); // attested credential data included
    }

    final data = BytesBuilder()
      ..add(rpIdHash)
      ..addByte(flags)
      ..add(authCounter.asBytes(type: IntType.int32));
    if (credentialData != null && credentialData.isNotEmpty) {
      data.add(credentialData);
    }

    if (clientDataHash != null && clientDataHash.isNotEmpty) {
      data.add(clientDataHash);
    }

    return data.toBytes();
  }

  /// Construct an AttestationObject per the WebAuthn spec
  /// @see https://www.w3.org/TR/webauthn/#sctn-generating-an-attestation-object
  /// A package self-attestation or "none" attestation will be returned
  /// @see https://www.w3.org/TR/webauthn/#sctn-attestation-formats
  Future<Attestation> _constructAttestation(
      AttestationType attestationType,
      Uint8List authenticatorData,
      Uint8List clientDataHash,
      String keyPairAlias,
      Signer<PrivateKey>? signer) async {
    // We are going to create a signature over the relevant data fields.
    // See https://www.w3.org/TR/webauthn/#sctn-attestation-formats
    // We need to sign the concatenation of the authenticationData and clientDataHash
    // The Attestation knows how to CBOR encode itself

    PrivateKey? privateKey;
    if (signer == null) {
      // Get the key for signing
      final keyPair = await _credentialSafe.getKeyPairByAlias(keyPairAlias);
      if (keyPair == null) {
        throw KeyPairNotFound(keyPairAlias);
      }
      privateKey = keyPair.privateKey;
    }

    final toSign = BytesBuilder()
      ..add(authenticatorData)
      ..add(clientDataHash);

    // Sanity check to make sure the data is the length we are expecting
    assert(toSign.length == authenticationDataLength + 32);

    // Sign our data
    final signatureBytes = _crypto.performSignature(toSign.toBytes(),
        privateKey: privateKey, signer: signer);

    // Sanity check on signature
    assert(signatureBytes.length >= minSignatureDataLength);

    switch (attestationType) {
      case AttestationType.none:
        return NoneAttestation(authenticatorData);
      case AttestationType.packed:
        return PackedSelfAttestation(authenticatorData, signatureBytes);
    }
  }

  Future<Assertion> _createAssertion(
    GetAssertionOptions options,
    Credential credential,
    Uint8List authenticatorData,
    Uint8List signature,
  ) async {
    return Assertion(
      selectedCredentialId: credential.keyId,
      authenticatorData: authenticatorData,
      signature: signature,
      selectedCredentialUserHandle: credential.userHandle,
    );
  }
}
