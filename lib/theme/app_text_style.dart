import 'package:flutter/material.dart';

class Fonts {
  static const String font = "Poppins";
}

class AppTextStyle {
  static TextStyle light({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w300,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle lightItalic({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w300,
      fontStyle: FontStyle.italic,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle regular({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w400,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle regularItalic({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w400,
      fontStyle: FontStyle.italic,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle medium({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w500,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle semiBold({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w600,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle bold({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w700,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle extraBold({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w800,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }

  static TextStyle heavy({
    Color? color,
    double? fontSize,
    TextOverflow? overflow,
  }) {
    return TextStyle(
      fontFamily: Fonts.font,
      fontWeight: FontWeight.w900,
      fontSize: fontSize,
      color: color,
      overflow: overflow,
    );
  }
}
