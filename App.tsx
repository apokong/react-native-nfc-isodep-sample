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

import React, {useState} from 'react';
import {
  Platform,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import NfcManager, {NfcError, NfcTech} from 'react-native-nfc-manager';
import Button from './app/components/Button';

function App(): JSX.Element {
  const AID = 'STA'; // 3 bytes
  const DEFAULT_DATA_CODE = 'EAL MKK 3 UE';
  const DEFAULT_KEYS = [15, 1];

  let _logStr: string = 'LOG TEXT\n';
  let _logIdx: number = 0;

  const toHexString = (bytes: number[]): string =>
    bytes.reduce(
      (acc, byte) => acc + ('00' + byte.toString(16).toUpperCase()).slice(-2),
      '',
    );

  const toBytes = (str: string): number[] => {
    var bytes: number[] = [];
    for (let i: number = 0; i < str.length; ++i) {
      bytes.push(str.charCodeAt(i));
    }
    return bytes;
  };

  const bytesToString = (bytes: number[]): string => {
    var result = '';
    for (var i = 0; i < bytes.length; ++i) {
      const byte = bytes[i];
      const text = byte.toString(16);
      result += (byte < 16 ? '%0' : '%') + text;
    }
    return decodeURIComponent(result);
  };

  const newAid = toBytes(AID);
  const defaultBytes2Write = toBytes(DEFAULT_DATA_CODE);

  const [logTxt, setLogTxt] = useState(_logStr);

  const log = (...args: any[]): void => {
    const _str = args.map(val => `${JSON.stringify(val)} \n`);
    _logStr += `\n⇒ LOG ${++_logIdx}\n${_str}`;
    setLogTxt(_logStr);
  };

  const parseRes = (res: number[]): {success: boolean; data: number[]} => ({
    success: toHexString(res.slice(-2)) === '9100',
    data: res.slice(0, -2),
  });

  const handleException = (ex: unknown): void => {
    if (ex instanceof NfcError.UserCancel) {
      // bypass
    } else if (ex instanceof NfcError.Timeout) {
      log('WARN: NFC Session Timeout');
    } else {
      log('WARN: NFC Error', ex);
    }
  };

  const cancelTechnologyRequest = async (): Promise<void> => {
    try {
      NfcManager.cancelTechnologyRequest();
    } catch (ex) {
      handleException(ex);
    }
  };

  const transceive = async (bytes: number[]) =>
    Platform.OS === 'ios'
      ? NfcManager.isoDepHandler.transceive(bytes)
      : NfcManager.transceive(bytes);

  const writeIsoDep = async (): Promise<void> => {
    log('writeIsoDep start');
    try {
      await NfcManager.requestTechnology(NfcTech.IsoDep);
      let tag = await NfcManager.getTag();
      log('tag data', JSON.stringify(tag));

      let resp;

      /* Select PICC Level App => 9100 = success */
      resp = await transceive([
        0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ]);
      log('Select PICC Level App', toHexString(resp));

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
      log('Create App', toHexString(resp));

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
      log('Select App', toHexString(resp));

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
      log('Create File', toHexString(resp));

      /* Write the data code */
      log('Writing', defaultBytes2Write);
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
      log('Write Data', toHexString(resp));
    } catch (ex) {
      handleException(ex);
    } finally {
      cancelTechnologyRequest();
    }
  };

  const readIsoDep = async (): Promise<void> => {
    log('readIsoDep start');
    try {
      cancelTechnologyRequest();

      await NfcManager.requestTechnology(NfcTech.IsoDep);
      let tag = await NfcManager.getTag();
      log('tag data', JSON.stringify(tag));

      let resp;

      /* Select PICC Level App => 9100 = success */
      resp = await transceive([
        0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      ]);
      log('Select PICC Level App', toHexString(resp));

      // /* List AIDs */
      // resp = await transceive([0x90, 0x6a, 0x00, 0x00, 0x00]);
      // log('All AIDs', toHexString(resp));

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
      log('Select App', toHexString(resp));

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
      log('Read Data', toHexString(resp));
      log('STORED DATA', bytesToString(readRes.data));
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
          <Text>{logTxt}</Text>
        </ScrollView>
        <Button onPress={writeIsoDep} title="Write" />
        <Button onPress={readIsoDep} title="Read" />
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFF',
  },
  view: {
    flex: 2,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 20,
    gap: 10,
  },
  scrollview: {
    flex: 2,
    width: '100%',
    backgroundColor: '#eee',
    padding: 10,
  },
});

export default App;
