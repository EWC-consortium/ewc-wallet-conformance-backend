import { expect } from 'chai';
import { createCredentialOfferConfig } from '../utils/routeUtils.js';

describe('Route Utils', () => {
  describe('createCredentialOfferConfig', () => {
    it('should set issuer_state for authorization code flow', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'authorization_code'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('authorization_code');
      expect(config.grants.authorization_code).to.have.property('issuer_state');
      expect(config.grants.authorization_code.issuer_state).to.equal('test-session-123');
      expect(config.grants.authorization_code).to.not.have.property('pre-authorized_code');
    });

    it('should set pre-authorized_code for pre-authorized code flow', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']).to.equal('test-session-123');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.not.have.property('issuer_state');
    });

    it('should include transaction code when specified', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        true,
        'authorization_code'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('authorization_code');
      expect(config.grants.authorization_code).to.have.property('issuer_state');
      expect(config.grants.authorization_code).to.have.property('tx_code');
      expect(config.grants.authorization_code.tx_code).to.have.property('input_mode');
      expect(config.grants.authorization_code.tx_code).to.have.property('length');
      expect(config.grants.authorization_code.tx_code).to.have.property('description');
    });

    it('should use default grant type when not specified', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123'
      );

      expect(config).to.have.property('grants');
      expect(config.grants).to.have.property('urn:ietf:params:oauth:grant-type:pre-authorized_code');
      expect(config.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']).to.have.property('pre-authorized_code');
    });

    it('should include credential configuration IDs', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'authorization_code'
      );

      expect(config).to.have.property('credential_configuration_ids');
      expect(config.credential_configuration_ids).to.be.an('array');
      expect(config.credential_configuration_ids).to.include('urn:eu.europa.ec.eudi:pid:1');
    });

    it('should include credential issuer URL', () => {
      const config = createCredentialOfferConfig(
        'urn:eu.europa.ec.eudi:pid:1',
        'test-session-123',
        false,
        'authorization_code'
      );

      expect(config).to.have.property('credential_issuer');
      expect(config.credential_issuer).to.be.a('string');
      expect(config.credential_issuer).to.match(/^https?:\/\//);
    });
  });
}); 