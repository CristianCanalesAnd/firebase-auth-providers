import 'package:flutter/material.dart';

import '../shared/constants.dart';
import '../theme/app_text_style.dart';

class PasswordTextField extends StatefulWidget {
  final TextEditingController passwordController;
  final String labelText;
  final String validatorText;
  final String? Function(String?)? validator;
  final Function(String?)? onChanged;
  final Function(String?)? onSaved;

  const PasswordTextField({
    super.key,
    required this.passwordController,
    required this.labelText,
    required this.validatorText,
    this.validator,
    this.onChanged,
    this.onSaved,
  });

  @override
  State<PasswordTextField> createState() => _PasswordTextFieldState();
}

class _PasswordTextFieldState extends State<PasswordTextField> {
  bool _obscureText = true;

  @override
  Widget build(BuildContext context) {
    return TextFormField(
      controller: widget.passwordController,
      onChanged: widget.onChanged,
      onSaved: widget.onSaved,
      decoration: InputDecoration(
        labelText: widget.labelText,
        suffixIconConstraints: const BoxConstraints(
          minHeight: 40,
          maxWidth: 40,
          minWidth: 40,
          maxHeight: 40,
        ),
        suffixIcon: buildSuffixIcon(),
      ),
      validator: _validatorDecorator,
      obscureText: _obscureText,
      style: AppTextStyle.regular(fontSize: 20),
    );
  }

  Widget buildSuffixIcon() {
    String image = _obscureText
        ? 'assets/images/common/password_visible.png'
        : 'assets/images/common/password_obscure.png';
    return GestureDetector(
      onTap: () => setState(() => _obscureText = !_obscureText),
      child: Padding(
        padding: const EdgeInsets.only(right: 10),
        child: Image.asset(image),
      ),
    );
  }

  String? _validatorDecorator(String? value) {
    if (widget.validator != null) {
      String? v = _validator(value);

      if (v != null) {
        return v;
      }

      return widget.validator!(v);
    }

    return _validator(value);
  }

  String? _validator(String? value) {
    if (value == null || value.isEmpty) {
      return widget.validatorText;
    } else if (value.length < Constants.minPasswordSize) {
      return 'Please enter at least ${Constants.minPasswordSize} characters';
    }
    return null;
  }
}
