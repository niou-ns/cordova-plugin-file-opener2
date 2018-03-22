/*
The MIT License (MIT)

Copyright (c) 2013 pwlin - pwlin05@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package io.github.pwlin.cordova.plugins.fileopener2;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Arrays;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.webkit.MimeTypeMap;

import io.github.pwlin.cordova.plugins.fileopener2.FileProvider;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CordovaResourceApi;

public class FileOpener2 extends CordovaPlugin {

	/**
	 * Executes the request and returns a boolean.
	 *
	 * @param action
	 *            The action to execute.
	 * @param args
	 *            JSONArry of arguments for the plugin.
	 * @param callbackContext
	 *            The callback context used when calling back into JavaScript.
	 * @return boolean.
	 */
	public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
		if (action.equals("open")) {
			String fileUrl = args.getString(0);
			String contentType = args.getString(1);
			Boolean openWithDefault = true;
			if(args.length() > 2){
				openWithDefault = args.getBoolean(2);
			}
			this._open(fileUrl, contentType, openWithDefault, callbackContext);
		}
		else if (action.equals("uninstall")) {
			this._uninstall(args.getString(0), callbackContext);
		}
		else if (action.equals("appIsInstalled")) {
			JSONObject successObj = new JSONObject();
			if (this._appIsInstalled(args.getString(0))) {
				successObj.put("status", PluginResult.Status.OK.ordinal());
				successObj.put("message", "Installed");
			}
			else {
				successObj.put("status", PluginResult.Status.NO_RESULT.ordinal());
				successObj.put("message", "Not installed");
			}
			callbackContext.success(successObj);
		}
		else {
			JSONObject errorObj = new JSONObject();
			errorObj.put("status", PluginResult.Status.INVALID_ACTION.ordinal());
			errorObj.put("message", "Invalid action");
			callbackContext.error(errorObj);
		}
		return true;
	}

	private void _open(String fileArg, String contentType, Boolean openWithDefault, CallbackContext callbackContext) throws JSONException {
		String fileName = "";
		try {
			CordovaResourceApi resourceApi = webView.getResourceApi();
			Uri fileUri = resourceApi.remapUri(Uri.parse(fileArg));
			fileName = this.stripFileProtocol(fileUri.toString());
		} catch (Exception e) {
			fileName = fileArg;
		}
		File file = new File(fileName);
		if (file.exists()) {
			try {
				Intent intent;
				if (contentType.equals("application/vnd.android.package-archive")) {
					// https://stackoverflow.com/questions/9637629/can-we-install-an-apk-from-a-contentprovider/9672282#9672282
					intent = new Intent(Intent.ACTION_INSTALL_PACKAGE);
					Uri path;
					if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
						path = Uri.fromFile(file);
					} else {
						Context context = cordova.getActivity().getApplicationContext();
						path = FileProvider.getUriForFile(context, cordova.getActivity().getPackageName() + ".opener.provider", file);
					}
					intent.setDataAndType(path, contentType);
					intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

				} else {
					intent = new Intent(Intent.ACTION_VIEW);
					Context context = cordova.getActivity().getApplicationContext();
					Uri path = FileProvider.getUriForFile(context, cordova.getActivity().getPackageName() + ".opener.provider", file);

					if (contentType.equals("null") || contentType.isEmpty()) {
					    String mimeType = null;
					    ContentResolver contentResolver = context.getContentResolver();
					    if (path.getScheme().equals(ContentResolver.SCHEME_CONTENT)) {
					        mimeType = contentResolver.getType(path);
					    } else {
					        String fileExtension = MimeTypeMap.getFileExtensionFromUrl(path.toString());
					        mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(
					                fileExtension.toLowerCase());
					    }

					    if (null == mimeType || mimeType.equals("application/octet-stream")) {
					        String extension = getFileExtFromBytes(file);
					        if (!extension.equals("UNKNOWN")) {
					            mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension.toLowerCase());
					            File fileTo = new File(fileName + '.' + extension.toLowerCase());
					            file.renameTo(fileTo);
					            file = new File(fileName + '.' + extension.toLowerCase());
					            path = FileProvider.getUriForFile(context, cordova.getActivity().getPackageName() + ".opener.provider", file);
					        }
					        if ((contentType.equals("null") || contentType.isEmpty()) && !extension.equals("UNKNOWN")) {
					            contentType = mimeType;
					        }
					    }

					}

					intent.setDataAndType(path, contentType);
					intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NO_HISTORY);

				}

				/*
				 * @see
				 * http://stackoverflow.com/questions/14321376/open-an-activity-from-a-cordovaplugin
				 */
				 if(openWithDefault){
					 cordova.getActivity().startActivity(intent);
				 }
				 else{
					 cordova.getActivity().startActivity(Intent.createChooser(intent, "Open File in..."));
				 }

				callbackContext.success();
			} catch (android.content.ActivityNotFoundException e) {
				JSONObject errorObj = new JSONObject();
				errorObj.put("status", PluginResult.Status.ERROR.ordinal());
				errorObj.put("message", "Activity not found: " + e.getMessage());
				callbackContext.error(errorObj);
			}
		} else {
			JSONObject errorObj = new JSONObject();
			errorObj.put("status", PluginResult.Status.ERROR.ordinal());
			errorObj.put("message", "File not found");
			callbackContext.error(errorObj);
		}
	}

	private void _uninstall(String packageId, CallbackContext callbackContext) throws JSONException {
		if (this._appIsInstalled(packageId)) {
			Intent intent = new Intent(Intent.ACTION_UNINSTALL_PACKAGE);
			intent.setData(Uri.parse("package:" + packageId));
			cordova.getActivity().startActivity(intent);
			callbackContext.success();
		}
		else {
			JSONObject errorObj = new JSONObject();
			errorObj.put("status", PluginResult.Status.ERROR.ordinal());
			errorObj.put("message", "This package is not installed");
			callbackContext.error(errorObj);
		}
	}

	private boolean _appIsInstalled(String packageId) {
		PackageManager pm = cordova.getActivity().getPackageManager();
        boolean appInstalled = false;
        try {
            pm.getPackageInfo(packageId, PackageManager.GET_ACTIVITIES);
            appInstalled = true;
        } catch (PackageManager.NameNotFoundException e) {
            appInstalled = false;
        }
        return appInstalled;
	}

	private String stripFileProtocol(String uriString) {
		if (uriString.startsWith("file://")) {
			uriString = uriString.substring(7);
		} else if (uriString.startsWith("content://")) {
			uriString = uriString.substring(10);
		}
		return uriString;
	}

  private static final int BUFFER_SIZE = 2048;
  private static final int MICROSOFT_OFFSET = 512;
  private static final int MAX_SIGNATURE_SIZE = 8;

  private static final int[] pdfSig   =   { 0x25, 0x50, 0x44, 0x46 };
  private static final int[] jpgSig   =   { 0xFF, 0xD8, 0xFF, 0xDB };
  private static final int[] jpegSig  =   { 0xFF, 0xD8, 0xFF, 0xE0 };
  private static final int[] pngSig   =   { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
  private static final int[] micSig   =   { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
  private static final int[] micxSig  =   { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 };
//    All the Microsoft Documents headers looks the same
//    private static final int[] xlsSig   =   { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
//    private static final int[] xlsxSig  =   { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 };
//    private static final int[] pptSig   =   { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
  private static final int[] docHead  =   { 0xEC, 0xA5, 0xC1, 0x00 };
  private static final int[] xlsHead  =   { 0xFD, 0xFF, 0xFF, 0xFF };
  private static final int[] pptHead  =   { 0x60, 0x21, 0x1B, 0xF0 };
  private static final int[] docxEnd  =   { 0x00, 0x77, 0x6F, 0x72, 0x64, 0x2F };
  private static final int[] xlsxEnd  =   { 0x00, 0x00, 0x78, 0x6C, 0x2F };
  private static final int[] pptxEnd  =   { 0x00, 0x00, 0x70, 0x70, 0x74, 0x2F };

  private static String getFileExtFromBytes(File f)  {
      String fileType = "UNKNOWN";
      byte[] buffer = new byte[BUFFER_SIZE];
      InputStream in = null;

      HashMap<String, int[]> signatureMap = new HashMap<String,int[]>();
      signatureMap.put("PDF", pdfSig);
      signatureMap.put("JPG", jpgSig);
      signatureMap.put("JPEG", jpegSig);
      signatureMap.put("PNG", pngSig);
      signatureMap.put("Microsoft", micSig);
      signatureMap.put("MicrosoftX", micxSig);

      try {
          in = new FileInputStream(f);
          int n = in.read(buffer, 0, BUFFER_SIZE);
          int m = n;
          while ((m < MAX_SIGNATURE_SIZE) && (n > 0)) {
              n = in.read(buffer, m, BUFFER_SIZE - m);
              m += n;
          }

          for (Iterator<String> i = signatureMap.keySet().iterator(); i.hasNext(); ) {
              String key = i.next();
              if (matchesSignature(signatureMap.get(key), buffer, m)) {
                  fileType = key;
                  break;
              }
          }

          if (fileType.equals("Microsoft")) {
              HashMap<String, int[]> microsoftMap = new HashMap<String,int[]>();
              microsoftMap.put("DOC", docHead);
              microsoftMap.put("XLS", xlsHead);
              microsoftMap.put("PPT", pptHead);

              String microsoftType = "UNKNOWN";
              byte[] microsoftBuffer = new byte[MAX_SIGNATURE_SIZE];

              int j = 0;
              for (int k = MICROSOFT_OFFSET; k < MICROSOFT_OFFSET + MAX_SIGNATURE_SIZE; k++) {
                  microsoftBuffer[j] = buffer[k];
                  j++;
              }

              for (Iterator<String> i = microsoftMap.keySet().iterator(); i.hasNext(); ) {
                  String key = i.next();
                  if (matchesSignature(microsoftMap.get(key), microsoftBuffer, MAX_SIGNATURE_SIZE)) {
                      microsoftType = key;
                      break;
                  }
              }

              return microsoftType;
          }

          if (fileType.equals("MicrosoftX")) {
              HashMap<String, int[]> microsoftMap = new HashMap<String,int[]>();
              microsoftMap.put("DOCX", docxEnd);
              microsoftMap.put("XLSX", xlsxEnd);
              microsoftMap.put("PPTX", pptxEnd);

              String microsoftType = "UNKNOWN";
              int size = in.available();
              int counter = 0;
              byte[] _temp = new byte[size];
              in.read(_temp, size - BUFFER_SIZE, BUFFER_SIZE);

              byte[] microsoftBuffer = Arrays.copyOfRange(_temp, size - BUFFER_SIZE, size);

              for (Iterator<String> i = microsoftMap.keySet().iterator(); i.hasNext(); ) {
                  String key = i.next();
                  if (matchesDeepSignature(microsoftMap.get(key), microsoftBuffer)) {
                      microsoftType = key;
                      break;
                  }
              }

              return microsoftType;
          }

          in.close();
      } catch (IOException e) {
          e.printStackTrace();
      }
      return fileType;
  }

  private static boolean matchesSignature(int[] signature, byte[] buffer, int size) {
      if (size < signature.length) {
          return false;
      }

      boolean b = true;
      for (int i = 0; i < signature.length; i++) {
          if (signature[i] != (0x00ff & buffer[i])) {
              b = false;
              break;
          }
      }

      return b;
  }

  private static boolean matchesDeepSignature(int[] signature, byte[] buffer) {

      boolean hasMatch = true;
      for (int i = 0; i < buffer.length; i++) {
          if (signature[0] == (0x00ff & buffer[i])) {
              hasMatch = true;
              for (int k = 1; k < signature.length; k++) {
                  if (signature[k] != (0x00ff & buffer[k + i])) {
                      hasMatch = false;
                      break;
                  }
              }
              if (hasMatch) {
                  break;
              }
          }
      }

      return hasMatch;
  }

}
