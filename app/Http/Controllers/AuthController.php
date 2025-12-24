<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    // ================= REGISTER =================
    public function register(Request $request)
    {
        $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users,email',
            'password' => 'required|min:6',
        ]);

        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Buat token menggunakan Sanctum
        $token = $user->createToken('auth-token')->plainTextToken;

        return response()->json([
            'message' => 'Register berhasil',
            'user'    => $user,
            'token'   => $token,
        ], 201);
    }

    // ================= LOGIN =================
    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'Email atau password salah'
            ], 401);
        }

        $user = Auth::user();
        
        // Buat token menggunakan Sanctum
        $token = $user->createToken('auth-token')->plainTextToken;

        return response()->json([
            'message' => 'Login berhasil',
            'user'    => $user,
            'token'   => $token,
        ]);
    }

    // ================= LOGOUT =================
    public function logout(Request $request)
    {
        // Hapus token saat ini
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logout berhasil'
        ]);
    }

    // [FUNGSI LOGIN ADMIN]
    public function adminLogin(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // Cari user berdasarkan email
        $user = User::where('email', $request->email)->first();

        // Validasi: Cek apakah user ada, password cocok, dan role adalah admin
        if (!$user || !Hash::check($request->password, $user->password) || $user->role !== 'admin') {
            return response()->json([
                'message' => 'Login gagal. Email/Password salah atau Anda bukan Admin.'
            ], 401);
        }

        // Buat Token
        $token = $user->createToken('admin_token')->plainTextToken;

        return response()->json([
            'message' => 'Login Admin Berhasil',
            'user' => $user,
            'token' => $token
        ], 200);
    }

    // ================= REGISTER ADMIN =================
    public function adminRegister(Request $request)
    {
        // Kode admin rahasia (harus sama dengan frontend)
        $validAdminCode = '177013';

        $request->validate([
            'name'       => 'required|string|max:255',
            'email'      => 'required|email|unique:users,email',
            'password'   => 'required|min:8',
            'admin_code' => 'required|string',
        ]);

        // Validasi kode admin
        if ($request->admin_code !== $validAdminCode) {
            return response()->json([
                'message' => 'Kode admin tidak valid'
            ], 403);
        }

        // Buat user dengan role admin
        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
            'role'     => 'admin',  // Set role sebagai admin
            'status'   => 'active',
        ]);

        // Buat token
        $token = $user->createToken('admin_token')->plainTextToken;

        return response()->json([
            'message' => 'Registrasi Admin Berhasil',
            'user'    => $user,
            'token'   => $token,
        ], 201);
    }
}
