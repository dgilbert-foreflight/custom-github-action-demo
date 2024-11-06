import * as core from '@actions/core'
import * as exec from '@actions/exec'

/**
 * Create a keychain and set the default timeout
 * @returns {Promise<void>} Resolves when the keychain is created
 */
export async function createKeychain(
  keychainName: string,
  keychainPassword: string,
  keychainTimeout: number
): Promise<void> {
  return new Promise(async (resolve, reject) => {
    core.setSecret(keychainPassword)

    // Delete the keychain (if it already exists)
    try {
      await deleteKeychain(keychainName)
    } catch (error) {
      core.debug(`Keychain ${keychainName} does not exist`)
    }

    try {
      // Create the keychain
      core.debug(`Creating keychain ${keychainName}`)
      await exec.exec('security', [
        'create-keychain',
        '-p', keychainPassword,
        keychainName
      ])
      core.info(`Keychain ${keychainName} created`)

      // Set the default keychain - TODO: This might not be needed / smart.
      // core.debug(`Setting default keychain to ${keychainName}`)
      // await exec.exec('security', [
      //   'default-keychain',
      //   '-s', 'login.keychain', keychainName
      // ])
      // core.info(`Default keychain set to ${keychainName}`)
      
      // Unlock the keychain
      core.debug(`Unlocking keychain ${keychainName}`)
      await exec.exec('security', [
        'unlock-keychain',
        '-p', keychainPassword,
        keychainName
      ])

      // Set the keychain timeout
      core.debug(`Setting keychain timeout to ${keychainTimeout} seconds`)
      await exec.exec('security', [
        'set-keychain-settings',
        '-t', keychainTimeout.toString(),
        '-u',keychainName
      ])

      // Reveal the keychain to the user
      core.debug(`Revealing keychain ${keychainName} to the user`)
      await exec.exec('security', [
        'list-keychains',
        '-d', 'user',
        '-s','login.keychain', keychainName
      ])
    } catch (error) {
      reject(error)
    }

    // Set outputs for other workflow steps to use
    core.setOutput('keychain-name', keychainName)

    resolve()
  })
}

/**
 * Deletes a keychain
 * @returns {Promise<void>} Resolves when the keychain is deleted
 */
export async function deleteKeychain(keychainName: string): Promise<void> {
  return new Promise(async (resolve, reject) => {
    try {
      core.debug(`Deleting keychain ${keychainName}`)
      await exec.exec('security', ['delete-keychain', keychainName])
      core.info(`Keychain ${keychainName} deleted`)
    } catch (error) {
      reject(error)
    }

    resolve()
  })
}

/**
 * Imports a certificate into the keychain
 * @returns {Promise<void>} Resolves when the certificate is imported
 */
export async function importCertificate(
  certificatePath: string,
  certificatePassphrase: string,
  keychainName: string,
  keychainPassword: string
): Promise<void> {
  return new Promise(async (resolve, reject) => {
    core.setSecret(certificatePassphrase)
    core.setSecret(keychainPassword)

    try {
      core.debug(`Importing ${certificatePath} into keychain ${keychainName}`)
      await exec.exec('security', [
        'import', certificatePath,
        '-P', certificatePassphrase,
        '-k', keychainName,
        '-t', 'cert',
        '-f', 'pkcs12',
        '-T', '/usr/bin/codesign',
        '-x'
      ])

      // Give signing tools access to the signing key
      core.debug('Setting key-partition-list')
      await exec.exec('security', [
        'set-key-partition-list',
        '-S', 'apple-tool:,apple:,codesign:',
        '-s',
        '-k', keychainPassword,
        keychainName
      ])
    } catch (error) {
      reject(error)
    }

    resolve()
  })
}

/**
 * Display Certificates in the keychain
 * @returns {Promise<string[]>} Resolves with an array of certificate names
 */
export async function listCertificates(keychainName: string): Promise<string[]> {
  return new Promise(async (resolve, reject) => {
    try {
      const { stdout } = await exec.getExecOutput('security', [
        'find-certificate', 
        '-a',
        keychainName
      ])

      // Look for certificates with labels like "Apple Development" or "Apple Distribution"
      const lablRegex = /"labl"<blob>="([^"]*(?:Development|Distribution|Mac|iPhone)[^"]*)"/g
      let match: RegExpExecArray | null
      const certificateLabels = []

      while ((match = lablRegex.exec(stdout)) !== null) {
        certificateLabels.push(match[1])
      }

      resolve(certificateLabels)
    } catch (error) {
      reject(error)
    }
  })
}
