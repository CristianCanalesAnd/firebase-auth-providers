import 'package:firebase_auth/firebase_auth.dart';

abstract class AuthRepository {
  Future<User> logInWithEmailAndPassword({
    required String email,
    required String password,
  });

  Future<User> signUpWithEmailAndPassword({
    required String email,
    required String password,
  });

  Future<User?> signInWithGoogle();

  Future<User?> signInWithApple();

  Future<void> signOut();
}
