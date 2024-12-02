import 'package:email_password_login/theme/app_text_style.dart';
import 'package:email_password_login/widgets/email_text_field.dart';
import 'package:email_password_login/widgets/password_text_field.dart';
import 'package:flutter/material.dart';

import '../../../../widgets/custom_button.dart';
import '../../../../widgets/social_media.dart';
import '../../../home/home_page.dart';
import '../../services/auth_service.dart';
import 'signup_page.dart';

class LogInPage extends StatefulWidget {
  const LogInPage({super.key});

  @override
  State<LogInPage> createState() => _LogInPageState();
}

class _LogInPageState extends State<LogInPage> {
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
                    "Log In Page",
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
                    title: 'Log In',
                    onPressed: _onLoginPressed,
                  ),
                  const SizedBox(height: 40),
                  SocialMedia(
                    onGooglePressed: _onGooglePressed,
                    onApplePressed: _onApplePressed,
                  ),
                  const SizedBox(height: 80),
                  GestureDetector(
                    onTap: _onSignUpPressed,
                    child: Text(
                      "Sign Up",
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
  Future<void> _onLoginPressed() async {
    if (_formKey.currentState!.validate()) {
      _formKey.currentState!.save();

      final email = _emailController.text;
      final password = _passwordController.text;

      final result = await _authService.logInWithEmailAndPassword(
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

  void _onSignUpPressed() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const SignUpPage(),
      ),
    );
  }
}
