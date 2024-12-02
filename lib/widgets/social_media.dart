import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/app_text_style.dart';
import 'social_card.dart';

class SocialMedia extends StatelessWidget {
  final Function()? onGooglePressed;
  final Function()? onApplePressed;

  const SocialMedia({
    super.key,
    this.onGooglePressed,
    this.onApplePressed,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        buildDescription(),
        const SizedBox(height: 20),
        buildSocial(),
      ],
    );
  }

  Widget buildDescription() {
    return Text(
      'Or continue with social account',
      style: AppTextStyle.regular(
        color: AppColors.gray,
        fontSize: 15,
      ),
    );
  }

  Widget buildSocial() {
    return Row(
      children: [
        Expanded(
          child: SocialCard(
            title: "Google",
            image: "assets/images/social_media/google.png",
            onPressed: onGooglePressed,
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: SocialCard(
            title: "Apple",
            image: "assets/images/social_media/apple.png",
            onPressed: onApplePressed,
          ),
        ),
      ],
    );
  }
}
