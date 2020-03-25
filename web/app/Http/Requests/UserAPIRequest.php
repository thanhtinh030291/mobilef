<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Config;

class UserAPIRequest extends FormRequest
{

    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */

    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        
        $rules = [
            'profile_image' => 'mimes:jpeg,jpg,png,jpe|nullable|max:1999',
            'email' => 'email|required|max:100',
            'password' => 'required|string|min:6|max:16',
        ];

        // if (Route::currentRouteName() == 'updateInfo') {
        //     unset($rules['email'], $rules['password']);
        // }
        // if (Route::currentRouteName() == 'changePassword') {
        //     unset($rules['email']);
        //     $rules['password'] = $valid_password.'|confirmed';
        // }
        // if (Route::currentRouteName() == 'forgotPassword') {
        //     unset($rules['password']);
        // }
        // if (Route::currentRouteName() == 'resetPassword') {
        //     $rules['token'] = 'required';
        //     $rules['password'] = $valid_password.'|confirmed';
        // }

        return $rules;
    }
    protected function failedValidation(Validator $validator)
    {
        if (Request()->route()->getPrefix() == 'api') {
            $errors = (new ValidationException($validator))->errors();
            throw new HttpResponseException(response()->json(['status' => 'errors', 'message' => $errors,
            ], 400));
        }
    }
}
