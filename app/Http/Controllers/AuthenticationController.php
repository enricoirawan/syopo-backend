<?php

namespace App\Http\Controllers;

use App\Mail\SendRegisterOTP;
use Illuminate\Http\Request;
use App\ResponseFormatter;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;

class AuthenticationController extends Controller
{
    public function register()
    {
        $validator = \Validator::make(request()->all(), [
            "email" => "required|unique:users,email",
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error(400, $validator->errors());
        }

        do {
            $otp = rand(1000000, 9999999);
            $otpCount = User::where('otp_register', $otp)->count();
        } while ($otpCount > 0);

        $user = User::create([
            "email" => request()->email,
            "name" => request()->email,
            "otp_register" => $otp,
        ]);

        Mail::to($user->email)->send(new \App\Mail\SendRegisterOTP($user));

        return ResponseFormatter::success([
            "is_sent" => true,
        ]);
    }

    public function resendOtp()
    {
        $validator = \Validator::make(request()->all(), [
            "email" => "required|exists:users,email",
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error(400, $validator->errors());
        }

        $user = User::where('email', request()->email)->whereNotNull('otp_register')->first();
        if (is_null($user)) {
            return ResponseFormatter::error(400, null, [
                "User tidak ditemukan"
            ]);
        }

        do {
            $otp = rand(1000000, 9999999);
            $otpCount = User::where('otp_register', $otp)->count();
        } while ($otpCount > 0);

        $user->update([
            "otp_register" => $otp,
        ]);

        Mail::to($user->email)->send(new \App\Mail\SendRegisterOTP($user));

        return ResponseFormatter::success([
            "is_sent" => true,
        ]);
    }

    public function verifyOtp()
    {
        $validator = \Validator::make(request()->all(), [
            "email" => "required|exists:users,email",
            "otp" => "required|exists:users,otp_register",
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error(400, $validator->errors());
        }

        $user = User::where('email', request()->email)->where('otp_register', request()->otp)->count();
        if ($user > 0) {
            return ResponseFormatter::success([
                'is_correct' => true
            ]);
        }

        return ResponseFormatter::error(400, 'Invalid OTP');
    }

    public function verifyRegister()
    {
        $validator = \Validator::make(request()->all(), [
            "email" => "required|exists:users,email",
            "otp" => "required|exists:users,otp_register",
            "password" => "required|min:6|confirmed",
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error(400, $validator->errors());
        }

        $user = User::where('email', request()->email)->where('otp_register', request()->otp)->first();
        if (!is_null($user)) {
            $user->update([
                'otp_register' => null,
                'email_verified_at' => now(),
                'password' => bcrypt(request()->password)
            ]);

            $token = $user->createToken(config('app.name'))->plainTextToken;

            return ResponseFormatter::success([
                'token' => $token
            ]);
        }

        return ResponseFormatter::error(400, 'Invalid OTP');
    }

    public function login()
    {
        $validator = \Validator::make(request()->all(), [
            "phone_email" => "required",
            "password" => "required",
        ]);

        if ($validator->fails()) {
            return ResponseFormatter::error(400, $validator->errors());
        }

        $user = User::where('email', request()->phone_email)->orWhere('phone', request()->phone_email)->first();
        if (is_null($user)) {
            return ResponseFormatter::error(400, null, ["User tidak ditemukan"]);
        }

        $userPassword = $user->password;
        if (Hash::check(request()->password, $userPassword)) {
            $token = $user->createToken(config('app.name'))->plainTextToken;

            return ResponseFormatter::success([
                'token' => $token
            ]);
        }

        return ResponseFormatter::error(400, null, ["Password Salah"]);
    }
}
