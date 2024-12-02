import 'package:email_password_login/features/auth/email_password_login/pages/login_page.dart';
import 'package:email_password_login/features/auth/services/auth_service.dart';
import 'package:email_password_login/theme/app_text_style.dart';
import 'package:email_password_login/widgets/custom_button.dart';
import 'package:flutter/material.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _authService = AuthService();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          'Home Page',
          style: AppTextStyle.bold(fontSize: 32),
        ),
      ),
      body: SafeArea(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: CustomButton(
                title: "Sign Out",
                onPressed: _onSignOutPressed,
              ),
            ),
          ],
        ),
      ),
    );
  }

  //Functions
  Future<void> _onSignOutPressed() async {
    await _authService.signOut().then((_) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (context) => const LogInPage(),
        ),
      );
    });
  }
}
