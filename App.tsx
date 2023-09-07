/**
 * POC for writing data with isoDep
 *
 * using MIFARE DESFire EV1 (MF3ICD(H) 21/41/81)
 * https://neteril.org/files/M075031_desfire.pdf
 *
 * by Apo Kong, apokong@gmail.com
 *
 * @format
 */

import React, { useState } from "react";
import {
  Platform,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
} from "react-native";
import NfcManager, { NfcError, NfcTech } from "react-native-nfc-manager";
import Button from "./app/components/Button";
import CryptoJS from "crypto-js";

function App(): JSX.Element {
  const AID = "STA"; // 3 bytes
  const DEFAULT_DATA_CODE = "EAL MKK 3 UE";
  const DEFAULT_KEYS = [15, 1];
  const DEFAULT_MASTER_KEY = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

  let _logStr: string = "LOG TEXT\n";
  let _logIdx: number = 0;

  const bytesToHexString = (bytes: number[]): string =>
    bytes.reduce(
      (acc, byte) => acc + ("00" + byte.toString(16).toUpperCase()).slice(-2),
      ""
    );

  const hexStringToBytes = (str: string): number[] => {
    const result: number[] = [];
    while (str.length >= 2) {
      result.push(parseInt(str.substring(0, 2), 16));
      str = str.substring(2, str.length);
    }
    return result;
  };

  const stringToBytes = (str: string): number[] => {
    var bytes: number[] = [];
    for (let i: number = 0; i < str.length; ++i) {
      bytes.push(str.charCodeAt(i));
    }
    return bytes;
  };

  const bytesToString = (bytes: number[]): string => {
    var result = "";
    for (var i = 0; i < bytes.length; ++i) {
      const byte = bytes[i];
      const text = byte.toString(16);
      result += (byte < 16 ? "%0" : "%") + text;
    }
    return decodeURIComponent(result);
  };

  const newAid: number[] = stringToBytes(AID);
  const defaultBytes2Write: number[] = stringToBytes(DEFAULT_DATA_CODE);

  const [logTxt, setLogTxt] = useState<string>(_logStr);
  const log = (...args: any[]): void => {
    const _str = args.map((val) => `${JSON.stringify(val)} \n`);
    _logStr += `\n⇒ LOG ${++_logIdx}\n${_str}`;
    setLogTxt(_logStr);
  };

  const parseRes = (res: number[]): { success: boolean; data: number[] } => ({
    success: bytesToHexString(res.slice(-2)).startsWith("91"),
    data: res.slice(0, -2),
  });

  const handleException = (ex: unknown): void => {
    if (ex instanceof NfcError.UserCancel) {
      // bypass
    } else if (ex instanceof NfcError.Timeout) {
      log("WARN: NFC Session Timeout");
    } else {
      log("WARN: NFC Error", ex);
    }
  };

  const cancelTechnologyRequest = async (): Promise<void> => {
    try {
      NfcManager.cancelTechnologyRequest();
    } catch (ex) {
      handleException(ex);
    }
  };

  const transceive = async (bytes: number[]): Promise<number[]> =>
    Platform.OS === "ios"
      ? NfcManager.isoDepHandler.transceive(bytes)
      : NfcManager.transceive(bytes);

  const byteArrayToWordArray = (bytes: number[]): CryptoJS.lib.WordArray => {
    let wordArray: number[] = [];
    for (let i: number = 0; i < bytes.length; i++) {
      wordArray[(i / 4) | 0] |= bytes[i] << (24 - 8 * i);
    }
    return CryptoJS.lib.WordArray.create(wordArray, bytes.length);
  };

  const wordArrayToByteArray = (
    wordArray: CryptoJS.lib.WordArray
  ): number[] => {
    const byteArray: number[] = wordArray.words;
    const result: number[] = [],
      xFF: number = 0xff;
    for (let i = 0; i < byteArray.length; i++) {
      result[i * 4 + 0] = (byteArray[i] >> 24) & 0xff;
      result[i * 4 + 1] = (byteArray[i] >> 16) & 0xff;
      result[i * 4 + 2] = (byteArray[i] >> 8) & 0xff;
      result[i * 4 + 3] = byteArray[i] & 0xff;
    }
    return result;
  };

  const rotateToLast = (source: number[]): number[] => {
    const result: number[] = [...source];
    const last: number | undefined = result.shift();
    if (last) result.push(last);
    return result;
  };

  const rotateToFirst = (source: number[]): number[] => {
    const result: number[] = [...source];
    const first: number | undefined = result.pop();
    if (first) result.unshift(first);
    return result;
  };

  const randomBytes = (count: number): number[] =>
    Array.from({ length: count }, (_) => Math.floor(256 * Math.random()));

  const encryptDes = (
    message: number[],
    iv: number[],
    key = DEFAULT_MASTER_KEY
  ): number[] => {
    const encrypted: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt(
      byteArrayToWordArray(message),
      byteArrayToWordArray(key),
      {
        iv: byteArrayToWordArray(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding,
        blocksize: 64,
      }
    );
    const wordsBytes = wordArrayToByteArray(encrypted.ciphertext);
    return wordsBytes;
  };

  const decryptDes = (
    message: number[],
    iv: number[],
    key = DEFAULT_MASTER_KEY
  ): number[] => {
    const decrypted: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(
      { ciphertext: byteArrayToWordArray(message) },
      byteArrayToWordArray(key),
      {
        iv: byteArrayToWordArray(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.NoPadding,
        blocksize: 64,
      }
    );
    return wordArrayToByteArray(decrypted);
  };

  const authenIsoDep = async (): Promise<void> => {
    try {
      await NfcManager.requestTechnology(NfcTech.IsoDep);
      let tag = await NfcManager.getTag();
      log("tag data", JSON.stringify(tag));

      let resp, respObj;

      /* Select PICC Level App => 9100 = success */
      resp = await transceive([
        0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ]);
      log("Select PICC Level App", bytesToHexString(resp));

      /**
       * Authenticate
       *
       * ref: https://www.mifare.net/support/forum/topic/mifare-desfire-authentication/page/2/
       */
      // Start authenticate PICC
      resp = await transceive([0x90, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00]);
      respObj = parseRes(resp);
      console.log("Authenticate 1", bytesToHexString(resp), respObj);

      // Receive encrypted RndB from the card
      const rndB_enc: number[] = respObj.data;

      // Decrypt encrypted RndB (IV - 16 bytes of zeros)
      const key: number[] = DEFAULT_MASTER_KEY;
      const iv: number[] = key.slice(0, key.length / 2);
      const rndB: number[] = decryptDes(rndB_enc, iv);
      log("rndB", bytesToHexString(rndB));

      // Rotate RndB one byte to the end (RndB')
      const rndB_rot: number[] = rotateToLast(rndB);
      log("rndB_rot", bytesToHexString(rndB_rot));

      // Generate RndA
      const rndA: number[] = randomBytes(8);
      log("rndA", bytesToHexString(rndA));

      // Concatenate RndA and RndB'
      const rndAB: number[] = [...rndA, ...rndB_rot];
      log("rndAB", bytesToHexString(rndAB));

      // Encrypt concatenated value (IV - still 16 bytes of zeros)
      const rndAB_token: number[] = encryptDes(rndAB, iv);
      log("rndAB_token", bytesToHexString(rndAB_token));

      resp = await transceive([
        0x90,
        0xaf,
        0x00,
        0x00,
        16,
        // RndA+RndB'(16)
        ...rndAB_token,
        // le
        0x00,
      ]);
      respObj = parseRes(resp);
      log("Authenticate 2", bytesToHexString(resp), respObj);

      // The card responds successfully and return encrypted RndA'
      const rndA_enc: number[] = respObj.data;
      log("rndA_enc", bytesToHexString(rndA_enc));

      // Decrypt encrypted RndA' (IV - still 16 bytes of zeros)
      const rndA_dec: number[] = decryptDes(rndA_enc, iv);
      log("rndA_dec", bytesToHexString(rndA_dec));

      // Rotate my RndA one byte to the Begining (RndA')
      const rndA_rot: number[] = rotateToFirst(rndA_dec);
      log("rndA_rot", bytesToHexString(rndA_rot));

      // Success if the Decrypted Rotated RndA' is equal to my RndA
      if (bytesToHexString(rndA_rot) !== bytesToHexString(rndA)) {
        throw new Error("AUTHEN_FAIL");
      }
      log("AUTHEN SUCCESS :))");
    } catch (ex) {
      handleException(ex);
    } finally {
      cancelTechnologyRequest();
    }
  };

  const writeIsoDep = async (): Promise<void> => {
    log("writeIsoDep start");
    try {
      await NfcManager.requestTechnology(NfcTech.IsoDep);
      let tag = await NfcManager.getTag();
      log("tag data", JSON.stringify(tag));

      let resp, respObj;

      /* Select PICC Level App => 9100 = success */
      resp = await transceive([
        0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ]);
      log("Select PICC Level App", bytesToHexString(resp));

      /* Create application */
      resp = await transceive([
        0x90,
        0xca,
        0x00,
        0x00,
        // lc
        newAid.length + DEFAULT_KEYS.length,
        //
        ...newAid,
        // key Settings
        ...DEFAULT_KEYS,
        // le
        0x00,
      ]);
      log("Create App", bytesToHexString(resp));

      /* Select application */
      resp = await transceive([
        0x90,
        0x5a,
        0x00,
        0x00,
        // lc
        newAid.length,
        //
        ...newAid,
        // le
        0x00,
      ]);
      log("Select App", bytesToHexString(resp));

      /* Create File ID */
      resp = await transceive([
        0x90,
        0xcd,
        0x00,
        0x00,
        // lc
        7,
        // fileID(1)
        0x01,
        // comm. mode(1)
        0x03, // 2=plain text, use 3 for better security
        // access right(2)
        0xee,
        0xee,
        // file size(3)
        defaultBytes2Write.length,
        0x00,
        0x00,
        // le
        0x00,
      ]);
      log("Create File", bytesToHexString(resp));

      /* Write the data code */
      log("Writing", defaultBytes2Write);
      resp = await transceive([
        0x90,
        0x3d,
        0x00,
        0x00,
        // lc
        defaultBytes2Write.length + 7,
        // fileID(1)
        0x01,
        // offset(3)
        0x00,
        0x00,
        0x00,
        // length(3)
        defaultBytes2Write.length,
        0x00,
        0x00,
        // data: max 42 bytes
        ...defaultBytes2Write,
        // le
        0x00,
      ]);
      log("Write Data", bytesToHexString(resp));
    } catch (ex) {
      handleException(ex);
    } finally {
      cancelTechnologyRequest();
    }
  };

  const readIsoDep = async (): Promise<void> => {
    log("readIsoDep start");
    try {
      cancelTechnologyRequest();

      await NfcManager.requestTechnology(NfcTech.IsoDep);
      let tag = await NfcManager.getTag();
      log("tag data", JSON.stringify(tag));

      let resp;

      /* Select PICC Level App => 9100 = success */
      resp = await transceive([
        0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ]);
      log("Select PICC Level App", bytesToHexString(resp));

      // /* List AIDs */
      // resp = await transceive([0x90, 0x6a, 0x00, 0x00, 0x00]);
      // log('All AIDs', bytesToHexString(resp));

      /* Select application */
      resp = await transceive([
        0x90,
        0x5a,
        0x00,
        0x00,
        // lc
        newAid.length,
        //
        ...newAid,
        // le
        0x00,
      ]);
      log("Select App", bytesToHexString(resp));

      /* Read the data code */
      resp = await transceive([
        0x90,
        0xbd,
        0x00,
        0x00,
        // lc
        0x07,
        // fileID(1)
        0x01, // select the 1st file
        // offset(3)
        0x00,
        0x00,
        0x00,
        // length(3)
        0x00,
        0x00,
        0x00,
        // le
        0x00,
      ]);
      const readRes = parseRes(resp);
      log("Read Data", bytesToHexString(resp));
      log("STORED DATA", bytesToString(readRes.data));
    } catch (ex) {
      handleException(ex);
    } finally {
      cancelTechnologyRequest();
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <View style={styles.view}>
        <ScrollView style={styles.scrollview}>
          <Text style={styles.text}>{logTxt}</Text>
        </ScrollView>
        <Button onPress={authenIsoDep} title="Authen" />
        <Button onPress={writeIsoDep} title="Write" />
        <Button onPress={readIsoDep} title="Read" />
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#FFF",
  },
  view: {
    flex: 2,
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "space-between",
    padding: 20,
    gap: 10,
  },
  scrollview: {
    flex: 2,
    width: "100%",
    backgroundColor: "#eee",
    padding: 10,
  },
  text: {
    color: "#000",
  },
});

export default App;
