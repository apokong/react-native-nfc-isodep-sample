# react-native-nfc-isodep-sample

POC for writing data with isoDep, in React Native for iOS/Android

## Getting Started

> **Note**: Make sure you have completed the [React Native - Environment Setup](https://reactnative.dev/docs/environment-setup) instructions till "Creating a new application" step, before proceeding.

## Step 1: Installation

```sh
yarn install
cd ios && pod install && cd ../
```

## Step 2: Environment for the first time

### For Android

Open the android folder in Android Studio, and run with emulator

### For iOS

Open the ios/RN_NFC_POC.xcworkspace in XCode, or run the following scripts

```bash
xed -b ios
```

Run with ios simulator

## Run

Since NFC detection is not supported in emulators, we run on real device

### For Android

Get your device ID with

```bash
adb devices
```

Run the app onto the plugged in Android device with the device ID detected

```bash
npx react-native run-android --deviceId=1234567890ABCD
```

### For iOS

Run the app onto the plugged in iOS device with your device name

```bash
npx react-native run-ios --device "ABC's iPhone"
```

## POC Limitations

### Write

Only work on formatted NFC cards.
Try to firstly format your NFC cards to factory default, with other mobile apps (e.g. NXP Tag Writer).

### Read

Only work on NFC cards writen by the "Write" function

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT
