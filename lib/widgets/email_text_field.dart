import 'package:email_validator/email_validator.dart';
import 'package:flutter/material.dart';

class EmailTextField extends StatelessWidget {
  final TextEditingController emailController;
  final Function(String?)? onSaved;

  const EmailTextField({
    super.key,
    required this.emailController,
    this.onSaved,
  });

  @override
  Widget build(BuildContext context) {
    return TextFormField(
      controller: emailController,
      onSaved: onSaved,
      decoration: const InputDecoration(
        labelText: 'Email',
      ),
      validator: (email) {
        if (email == null || email.isEmpty) {
          return 'Please enter your email';
        } else if (!EmailValidator.validate(email)) {
          return 'Your email is not valid';
        }
        return null;
      },
      keyboardType: TextInputType.emailAddress,
    );
  }
}
