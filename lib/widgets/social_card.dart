import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/app_text_style.dart';

class SocialCard extends StatelessWidget {
  final String title;
  final String image;
  final Function()? onPressed;

  const SocialCard({
    super.key,
    required this.title,
    required this.image,
    this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return TextButton.icon(
      onPressed: onPressed,
      style: buildStyle(),
      icon: buildIcon(),
      label: buildLabel(),
    );
  }

  ButtonStyle buildStyle() {
    return ButtonStyle(
      foregroundColor: MaterialStateProperty.all(AppColors.gray),
      textStyle: MaterialStateProperty.all(
        const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
      ),
      padding: MaterialStateProperty.all(
        const EdgeInsets.symmetric(vertical: 20),
      ),
      shape: MaterialStateProperty.all(
        RoundedRectangleBorder(
          side: const BorderSide(
            color: AppColors.gray,
            width: 1,
          ),
          borderRadius: BorderRadius.circular(10),
        ),
      ),
    );
  }

  Widget buildIcon() {
    return Image.asset(image, width: 24, height: 24);
  }

  Widget buildLabel() {
    return Text(
      title,
      style: AppTextStyle.regular(
        color: AppColors.dark,
        fontSize: 16.5,
      ),
    );
  }
}
