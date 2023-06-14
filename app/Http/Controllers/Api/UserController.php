<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    /**
     * Create User
     * @param Request $request
     * @return User 
     */
    public function createUser(Request $request)
    {
        try {
            //Validated
            $validateUser = Validator::make($request->all(), 
            [   
                'avatar' => 'required',
                'type' => 'required',
                'open_id' => 'required',
                'name' => 'required',
                'email' => 'required',
                'password' => 'required|min:6'
               
            ]);

            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            //validated will have all user field values
            //we can save in the database
            $validated = $validateUser -> validated(); //

            $map=[];

            ///correo , telefono , google , facebook , apple
            $map['type'] = $validated['type'];
            $map['open_id']=$validated['open_id'];

            $user = User::where($map) -> first(); ///
            
            ///whether user has already loffed in or not
            //empty means does not exist
            //teh save the user in the database for first time

            if(empty($user -> id)) {
                //this certian user has never been in our database
                //our job is to assign the user in the database
                //this token is user id
                $validated["token"] = md5(uniqid().rand(10000 , 99999));
                //user first time created
                $validated['created_at'] = Carbon:: now();
                //encript password
                $validated['password'] = Hash::make($validated['password']);
                //returns the id of the row after saving
                $userID = User::insertGetId($validated);
                //users all the information
                $userInfo = User::where('id' , '=' , $userID) -> first();
                //
                $accessToken = $userInfo -> createToken (uniqid()) -> plainTextToken;

                $userInfo -> access_token = $accessToken;

                return response()->json([
                    'status' => true,
                    'message' => 'User Created Successfully',
                    'data' => $userInfo
                ], 200);
            }

            ///user previously has logged in app
            $accessToken = $user-> createToken(uniqid()) -> plaintTextToken;
            $user -> access_token =  $accessToken;
            User::where('open_id' , '=' , $validated['open_id']) -> update(['accesss_token'=>$accessToken]);

            return response()->json([
                'status' => true,
                'message' => 'User logged in  Successfully',
                'token' => $user  ///CUALQUIER COSA REVISAR ESTA LINEA 
            ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    /**
     * Login The User
     * @param Request $request
     * @return User
     */
    public function loginUser(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(), 
            [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            if(!Auth::attempt($request->only(['email', 'password']))){
                return response()->json([
                    'status' => false,
                    'message' => 'Email & Password does not match with our record.',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            return response()->json([
                'status' => true,
                'message' => 'User Logged In Successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
}