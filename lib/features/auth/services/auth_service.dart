import 'package:either_dart/either.dart';
import 'package:email_password_login/main.dart';
import 'package:firebase_auth/firebase_auth.dart';

import '../repositories/auth_repository.dart';
import '../repositories/firebase_auth_repository.dart';

class AuthService {
  late AuthRepository _authRepository;

  AuthService() {
    final firebaseAuth = FirebaseAuth.instanceFor(app: firebaseApp);
    _authRepository = FirebaseAuthRepository(firebaseAuth: firebaseAuth);
  }

  Future<Either<Failure, User>> logInWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    try {
      final user = await _authRepository.logInWithEmailAndPassword(
          email: email, password: password);

      return Right(user);
    } on Failure catch (failure) {
      return Left(failure);
    }
  }

  Future<Either<Failure, User>> signUpWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    try {
      final user = await _authRepository.signUpWithEmailAndPassword(
          email: email, password: password);

      return Right(user);
    } on Failure catch (failure) {
      return Left(failure);
    }
  }

  Future<Either<Failure, User?>> signInWithGoogle() async {
    try {
      final user = await _authRepository.signInWithGoogle();

      return Right(user);
    } on Failure catch (failure) {
      return Left(failure);
    }
  }

  Future<Either<Failure, User?>> signInWithApple() async {
    try {
      final user = await _authRepository.signInWithApple();

      return Right(user);
    } on Failure catch (failure) {
      return Left(failure);
    }
  }

  Future<void> signOut() async {
    await _authRepository.signOut();
  }
}
