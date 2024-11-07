import * as core from '@actions/core'
import {
  createKeychain,
  deleteKeychain,
  importCertificate,
  listCertificates
} from './keychain'
import { promises as fsPromises } from 'fs'
import { isMacOS } from '@actions/core/lib/platform'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  const keychainName: string =
    core.getInput('keychain-name', { required: true }) + '.keychain'
  const keychainPassword: string = core.getInput('keychain-password', {
    required: true
  })
  const keychainTimeout: number = parseInt(
    core.getInput('keychain-timeout', { required: true })
  )
  core.setSecret(keychainPassword)

  // Import the certificates
  const signingCertificates: string[] = core.getMultilineInput(
    'signing-certificates',
    { required: true }
  )
  const signingCertificatePassphrase: string = core.getInput(
    'signing-certificate-passphrase',
    { required: true }
  )
  const certificatePath = `${process.env.RUNNER_TEMP}/certificate.p12`
  core.setSecret(signingCertificatePassphrase)

  try {
    if (!isMacOS) {
      throw new Error(
        `${process.platform} not supported. This action is only supported on macOS`
      )
    }

    // Create the keychain
    await createKeychain(keychainName, keychainPassword, keychainTimeout)

    await core.group(
      `Importing ${signingCertificates.length} certificates`,
      async () => {
        for (let i = 0; i < signingCertificates.length; i++) {
          core.info(
            `Importing certificate ${i + 1} of ${signingCertificates.length}`
          )
          // Decode the certificate from base64
          const certificateData = Buffer.from(signingCertificates[i], 'base64')

          // Write the certificate to a temporary file
          await fsPromises.writeFile(certificatePath, certificateData)
          // Import the certificate to the keychain
          await importCertificate(
            certificatePath,
            signingCertificatePassphrase,
            keychainName,
            keychainPassword
          )
        }
        core.info('\x1b[32mCertificates imported successfully\x1b[0m')

        if (core.isDebug()) {
          // List the certificates in the keychain
          const certificates = await listCertificates(keychainName)
          core.info(
            `\x1b[33mCertificates in ${keychainName}: \n\x1b[0m` +
              certificates.map(cert => `\x1b[33m  * ${cert}\x1b[0m`).join('\n')
          )
        }
      }
    )
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) core.setFailed(error.message)
  } finally {
    if (!core.isDebug()) {
      // Cleanup the job
      core.info('\x1b[33mCleaning up\x1b[0m')
      await deleteKeychain(keychainName)

      // Delete the temporary certificate file
      await fsPromises.unlink(certificatePath)
    }
  }
}
