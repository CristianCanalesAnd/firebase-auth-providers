import 'package:flutter/material.dart';

import '../theme/app_text_style.dart';
import '../theme/button_theme.dart';

class CustomButton extends StatelessWidget {
  final String title;
  final Color color;
  final Color? disabledBackgroundColor;
  final double fontSize;
  final EdgeInsets padding;
  final double borderRadius;
  final Function()? onPressed;

  const CustomButton({
    super.key,
    required this.title,
    this.color = Colors.white,
    this.disabledBackgroundColor,
    this.fontSize = 18,
    this.padding = const EdgeInsets.symmetric(vertical: 16, horizontal: 20),
    this.borderRadius = 50,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      child: TextButton(
        onPressed: onPressed,
        style: BtnTheme.primaryBtn(padding: padding),
        child: Text(
          title,
          style: AppTextStyle.semiBold(
            fontSize: fontSize,
            color: color,
          ),
        ),
      ),
    );
  }
}
