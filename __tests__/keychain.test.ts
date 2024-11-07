// tests/keychain.test.ts
import * as core from '@actions/core'
import * as exec from '@actions/exec'
import {
  createKeychain,
  deleteKeychain,
  importCertificate,
  listCertificates
} from '../src/keychain'

// Mock the core and exec modules
jest.mock('@actions/core')
jest.mock('@actions/exec')

describe('Keychain Functions', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('createKeychain', () => {
    it('should create a keychain and set the timeout', async () => {
      ;(exec.exec as jest.Mock).mockResolvedValueOnce(0)

      await createKeychain('test.keychain', 'password', 300)

      expect(core.setSecret).toHaveBeenCalledWith('password')
      expect(exec.exec).toHaveBeenCalledWith('security', [
        'create-keychain',
        '-p',
        'password',
        'test.keychain'
      ])
      expect(exec.exec).toHaveBeenCalledWith('security', [
        'unlock-keychain',
        '-p',
        'password',
        'test.keychain'
      ])
      expect(exec.exec).toHaveBeenCalledWith('security', [
        'set-keychain-settings',
        '-t',
        '300',
        '-u',
        'test.keychain'
      ])
      expect(core.setOutput).toHaveBeenCalledWith(
        'keychain-name',
        'test.keychain'
      )
    })

    it('should handle errors when creating a keychain', async () => {
      ;(exec.exec as jest.Mock).mockRejectedValueOnce(
        new Error('Failed to create keychain')
      )

      try {
        await createKeychain('test.keychain', 'password', 300)
      } catch (error) {
        expect(error).toEqual(new Error('Failed to create keychain'))
      }
    })
  })

  describe('deleteKeychain', () => {
    it('should delete a keychain', async () => {
      ;(exec.exec as jest.Mock).mockResolvedValueOnce(0)

      await deleteKeychain('test.keychain')

      expect(exec.exec).toHaveBeenCalledWith('security', [
        'delete-keychain',
        'test.keychain'
      ])
    })

    it('should handle errors when deleting a keychain', async () => {
      ;(exec.exec as jest.Mock).mockRejectedValueOnce(
        new Error('Failed to delete keychain')
      )

      await expect(deleteKeychain('test.keychain')).rejects.toThrow(
        'Failed to delete keychain'
      )
    })
  })

  describe('importCertificate', () => {
    it('should import a certificate', async () => {
      ;(exec.exec as jest.Mock)
        .mockResolvedValueOnce(0)
        .mockResolvedValueOnce(0)

      await importCertificate(
        'cert.p12',
        'passphrase',
        'test.keychain',
        'password'
      )

      expect(exec.exec).toHaveBeenCalledWith('security', [
        'import',
        'cert.p12',
        '-P',
        'passphrase',
        '-k',
        'test.keychain',
        '-t',
        'cert',
        '-f',
        'pkcs12',
        '-T',
        '/usr/bin/codesign',
        '-x'
      ])
      expect(exec.exec).toHaveBeenCalledWith('security', [
        'set-key-partition-list',
        '-S',
        'apple-tool:,apple:,codesign:',
        '-s',
        '-k',
        'password',
        'test.keychain'
      ])
    })

    it('should handle errors when importing a certificate', async () => {
      ;(exec.exec as jest.Mock).mockRejectedValueOnce(
        new Error('Failed to import certificate')
      )

      await expect(
        importCertificate('cert.p12', 'passphrase', 'test.keychain', 'password')
      ).rejects.toThrow('Failed to import certificate')
    })
  })

  describe('listCertificates', () => {
    it('should list certificates in a keychain', async () => {
      const mockOutput = {
        stdout:
          '"labl"<blob>="Apple Development: Cert1"\n"labl"<blob>="Apple Distribution: Cert2"',
        exitCode: 0,
        stderr: ''
      }
      jest.spyOn(exec, 'getExecOutput').mockResolvedValueOnce(mockOutput)

      const certificates = await listCertificates('test.keychain')

      expect(exec.getExecOutput).toHaveBeenCalledWith('security', [
        'find-certificate',
        '-a',
        'test.keychain'
      ])
      expect(certificates).toEqual([
        'Apple Development: Cert1',
        'Apple Distribution: Cert2'
      ])
    })

    it('should handle errors when listing certificates', async () => {
      jest
        .spyOn(exec, 'getExecOutput')
        .mockRejectedValueOnce(new Error('Failed to list certificates'))

      await expect(listCertificates('test.keychain')).rejects.toThrow(
        'Failed to list certificates'
      )
    })
  })
})
