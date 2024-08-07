import 'dart:typed_data';

import 'package:json_annotation/json_annotation.dart';
import '../models/converters/user_id_converter.dart';

part 'generated/user_entity.g.dart';

/// Information from the relying party about the user that the
/// operation relates to
@JsonSerializable()
class UserEntity {
  UserEntity({
    required this.id,
    required this.displayName,
    required this.name,
  });

  @UserIdConverter()
  Uint8List id;
  String displayName;
  String name;

  factory UserEntity.fromJson(Map<String, dynamic> json) =>
      _$UserEntityFromJson(json);

  Map<String, dynamic> toJson() => _$UserEntityToJson(this);
}
