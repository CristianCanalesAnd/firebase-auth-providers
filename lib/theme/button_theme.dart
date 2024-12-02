import 'package:flutter/material.dart';

import 'app_colors.dart';
import 'app_text_style.dart';

class BtnTheme {
  static ButtonStyle primaryBtn({required EdgeInsets? padding}) {
    return ButtonStyle(
      backgroundColor: MaterialStateProperty.all(AppColors.primary),
      foregroundColor: MaterialStateProperty.all(AppColors.white),
      textStyle: MaterialStateProperty.all(
        AppTextStyle.regular(fontSize: 16),
      ),
      padding: MaterialStateProperty.all(padding),
      shape: MaterialStateProperty.all(
        RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
      ),
    );
  }
}
