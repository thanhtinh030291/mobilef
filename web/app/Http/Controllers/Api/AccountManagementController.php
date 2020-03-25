<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\UserAPIRequest;
use App\Password_resets;
use App\User;
use Carbon\Carbon;
use Config;
use DB;
use Hash;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Storage;

use Illuminate\Http\Request;
use JWTAuth;
use JWTAuthException;


class AccountManagementController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'forgotPassword', 'resetPassword', 'checkLink']]);

    }
    public function login(UserAPIRequest $request)
    {
        $credentials = $request->only('email', 'password');
        $token = null;
        try {
            if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['invalid_email_or_password'], 422);
            }
        } catch (JWTAuthException $e) {
            return response()->json(['failed_to_create_token'], 500);
        }
        return response()->json(compact('token'));
    }

    public function getAuthUser()
    {
        $user = JWTAuth::user();
        return response()->json(['status' => 'success', 'user' => $user], 200);
        
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function updateInfo(UserAPIRequest $request, $id)
    {
        $dataNew = $request->only('email', 'name', 'profile_image', 'company_name', 'mobile', 'address');
        $upLoadPath = Config::get('constants.uploadDirectory.User');
        $request->validated();
        $newImage = request()->profile_image;
        // handle file upload
        if ($newImage) {
            //get file name with extension
            $fileNameWithExt = $newImage->getClientOriginalName();
            $fileNameToStore = time() . $fileNameWithExt;
            $newImage->storeAs($upLoadPath, $fileNameToStore);
        }
        $user = User::findOrFail($id);
        if ($newImage) {
            Storage::delete($upLoadPath . '/' . $user->profile_image);
            $dataNew['profile_image'] = $fileNameToStore;
        }
        $user = User::updateOrCreate(['id' => $id], $dataNew);
        $res = ['status' => 'success', 'message' => __('web.update_success'), 'user' => $user];
        return response($res);
        /**
         * @OA\Post(
         *     path="/updateInfo",
         *     summary="Update information user",
         *     tags={"User"},
         *     description="Show user of the system",
         *     @OA\Parameter(
         *         name="query",
         *         in="query",
         *         description="Nguyen van A",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="company_name",
         *         in="query",
         *         description="Mor SJC",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="mobile",
         *         in="query",
         *         description="090909090",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="address",
         *         in="query",
         *         description="Viet Nam",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Response(
         *         response=200,
         *         description="successful operation",
         *         @OA\JsonContent(),
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Invalid request",
         *         @OA\JsonContent(),
         *     ),
         *     security={{"bearerAuth":{}}}
         * )
         */
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */

    public function changePassword(UserAPIRequest $request, $id)
    {
        $data = $request->only('old_password', 'password', 'password_confirmation');
        $user = User::findOrFail($id);
        if (!Hash::check($request->old_password, $user->password)) {
            return response()->json(['status' => 'error', 'message' => __('web.password_old_incorrect')], 401);
        }
        $user->password = bcrypt($request->password);
        $user->save();
        return response()->json(['status' => 'success', 'message' => __('web.change_password_success')], 200);
        /**
         * @OA\Post(
         *     path="/changePassword",
         *     summary="Change password user",
         *     tags={"User"},
         *     description="Change password user to the system",
         *     @OA\Parameter(
         *         name="old_password",
         *         in="query",
         *         description="Old password",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="password",
         *         in="query",
         *         description=" New password",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="password_confirmation",
         *         in="query",
         *         description="Password confirmation",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Response(
         *         response=200,
         *         description="successful operation",
         *         @OA\JsonContent(),
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Invalid request",
         *         @OA\JsonContent(),
         *     ),
         *     security={{"bearerAuth":{}}}
         * )
         */
    }
    public function logout()
    {
        auth('api')->logout();
        return response()->json(['status' => 'success', 'message' => __('web.logout_success')], 200);
        /**
         * @OA\Post(
         *     path="/logout",
         *     summary="Logout user",
         *     tags={"User"},
         *     description="Logout user to the system",
         *     @OA\Response(
         *         response=200,
         *         description="successful operation",
         *         @OA\JsonContent(),
         *     ),
         *     security={{"bearerAuth":{}}}
         * )
         */
    }

    public function forgotPassword(UserAPIRequest $request)
    {
        $accountActive = Config::get('constants.accountActive');
        $data = $request->only('email');
        $user = User::where('email', $data['email'])->first();
        if ($user == null) {
            return response()->json(['status' => 'error', 'message' => __('web.email_exit')], 200);
        } elseif ($user->status == $accountActive) {
            $ramdom = str_random(60);
            Password_resets::Create([
                'email' => $data['email'],
                'token' => $ramdom,
                'created_at' => now(),
            ]);
            $data = [
                'user' => $user,
                'action_url' => url("/forgotpassword/{$ramdom}")
            ];
            sendEmail($user, $data, 'templateEmail.forgotPassTemplate' , __('web.reset_password'));
            return response()->json(['status' => 'success', 'message' => __('web.check_email')], 200);
        } else {
            return response()->json(['status' => 'error', 'message' => __('web.not_activated')], 200);
        }
        /**
         * @OA\Post(
         *     path="/forgotpassword",
         *     summary="Send mail user link forgot password ",
         *     tags={"User"},
         *     description="Send mail user link forgot password ",
         *     @OA\Parameter(
         *         name="email",
         *         in="query",
         *         description="abc@gmail.com",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Response(
         *         response=200,
         *         description="successful operation",
         *         @OA\JsonContent(),
         *     ),
         * )
         */
    }
    public function checkLink($token)
    {
        $effective_time = Config::get('constants.effective_time');
        $passwordReset = DB::table('password_resets')->where('token', $token)->first();
        if (!$passwordReset) {
            return response()->json([
                'status' => 'error',
                'message' => __('web.token_invalid'),
            ], 401);
        }

        if (Carbon::parse($passwordReset->created_at)->addMinutes($effective_time)->isPast()) {
            $passwordReset->delete();
            return response()->json([
                'status' => 'error',
                'message' => __('web.token_invalid'),
            ], 401);
        }
        return response()->json(['status' => 'success', 'data' => $passwordReset], 200);
        /**
         * @OA\Get(
         *     path="checklink/{token}",
         *     summary="Check link have token  ",
         *     tags={"User"},
         *     description="Check link have token ",
         *     @OA\Parameter(
         *         name="token",
         *         in="path",
         *         description="token",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Response(
         *         response=200,
         *         description="successful operation",
         *         @OA\JsonContent(),
         *     ),
         * )
         */
    }
    public function resetPassword(UserAPIRequest $request)
    {
        $data = $request->only('token', 'email', 'password', 'password_confirmation');
        $user = User::where('email', $request->email)->first();
        $user->password = bcrypt($request->password);
        $user->save();
        return response()->json(['status' => 'success', 'message' => __('web.change_password_success')], 200);
        /**
         * @OA\Post(
         *     path="/resetPassword",
         *     summary="Reset password user",
         *     tags={"User"},
         *     description="Reset password user to the system",
         *     @OA\Parameter(
         *         name="token",
         *         in="query",
         *         description="token",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="email",
         *         in="query",
         *         description="Email",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="password",
         *         in="query",
         *         description=" New password",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Parameter(
         *         name="password_confirmation",
         *         in="query",
         *         description="Password confirmation",
         *         required=true,
         *         @OA\Schema(
         *           type="string",
         *         ),
         *     ),
         *     @OA\Response(
         *         response=200,
         *         description="successful operation",
         *         @OA\JsonContent(),
         *     ),
         *     @OA\Response(
         *         response="401",
         *         description="Invalid request",
         *         @OA\JsonContent(),
         *     ),
         * )
         */
    }


    public function refresh()
    {
        return response(JWTAuth::getToken(), Response::HTTP_OK);
    }
    public function guard()
    {
        return Auth::guard();
    }
    protected function respondWithToken($token)
    {
        return ([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60,
            'user' => auth('api')->user(),
        ]);
    }
}
