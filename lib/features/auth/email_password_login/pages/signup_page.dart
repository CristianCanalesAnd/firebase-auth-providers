import 'package:email_password_login/features/auth/services/auth_service.dart';
import 'package:email_password_login/features/home/home_page.dart';
import 'package:email_password_login/theme/app_text_style.dart';
import 'package:email_password_login/widgets/email_text_field.dart';
import 'package:email_password_login/widgets/password_text_field.dart';
import 'package:flutter/material.dart';

import '../../../../widgets/custom_button.dart';
import '../../../../widgets/social_media.dart';

class SignUpPage extends StatefulWidget {
  const SignUpPage({super.key});

  @override
  State<SignUpPage> createState() => _SignUpPagePageState();
}

class _SignUpPagePageState extends State<SignUpPage> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  final _authService = AuthService();

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => FocusScope.of(context).unfocus(),
      child: Scaffold(
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
            child: Form(
              key: _formKey,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    "Sign Up Page",
                    style: AppTextStyle.bold(fontSize: 32),
                  ),
                  const SizedBox(height: 20),
                  EmailTextField(
                    emailController: _emailController,
                  ),
                  PasswordTextField(
                    passwordController: _passwordController,
                    labelText: 'Password',
                    validatorText: 'Password enter your password',
                  ),
                  const SizedBox(height: 40),
                  CustomButton(
                    title: 'Sign Up',
                    onPressed: _onSignUpPressed,
                  ),
                  const SizedBox(height: 40),
                  SocialMedia(
                    onGooglePressed: _onGooglePressed,
                    onApplePressed: _onApplePressed,
                  ),
                  const SizedBox(height: 80),
                  GestureDetector(
                    onTap: _onLogInPressed,
                    child: Text(
                      "Log In",
                      style: AppTextStyle.bold(fontSize: 18),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  // Functions
  Future<void> _onSignUpPressed() async {
    if (_formKey.currentState!.validate()) {
      _formKey.currentState!.save();

      final email = _emailController.text;
      final password = _passwordController.text;

      final result = await _authService.signUpWithEmailAndPassword(
        email: email,
        password: password,
      );

      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              backgroundColor: Colors.red,
              duration: const Duration(seconds: 1),
              content: Text(
                failure.message,
                style: AppTextStyle.regular(fontSize: 18),
              ),
            ),
          );
        },
        (user) {
          Navigator.of(context).pop();

          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              backgroundColor: Colors.green,
              duration: Duration(seconds: 1),
              content: Text('User sign up successfully'),
            ),
          );
        },
      );
    }
  }

  Future<void> _onGooglePressed() async {
    final result = await _authService.signInWithGoogle();

    result.fold(
      (failure) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 1),
            content: Text(
              failure.message,
              style: AppTextStyle.regular(fontSize: 18),
            ),
          ),
        );
      },
      (user) {
        if (user == null) {
          return;
        }

        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            backgroundColor: Colors.green,
            duration: Duration(seconds: 1),
            content: Text('User logged in successfully'),
          ),
        );

        Navigator.of(context).pushReplacement(
          MaterialPageRoute(
            builder: (context) => const HomePage(),
          ),
        );
      },
    );
  }

  Future<void> _onApplePressed() async {
    final result = await _authService.signInWithApple();

    result.fold(
      (failure) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 1),
            content: Text(
              failure.message,
              style: AppTextStyle.regular(fontSize: 18),
            ),
          ),
        );
      },
      (user) {
        if (user == null) {
          return;
        }

        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            backgroundColor: Colors.green,
            duration: Duration(seconds: 1),
            content: Text('User logged in successfully'),
          ),
        );

        Navigator.of(context).pushReplacement(
          MaterialPageRoute(
            builder: (context) => const HomePage(),
          ),
        );
      },
    );
  }

  void _onLogInPressed() {
    Navigator.of(context).pop();
  }
}
