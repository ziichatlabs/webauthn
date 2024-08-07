import 'dart:convert';
import 'dart:typed_data';

import 'package:json_annotation/json_annotation.dart';

class UserIdConverter implements JsonConverter<Uint8List, String> {
  const UserIdConverter();

  @override
  Uint8List fromJson(String json) => utf8.encode(json);

  @override
  String toJson(Uint8List object) => utf8.decode(object);
}
