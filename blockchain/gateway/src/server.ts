import express, { Request, Response } from "express";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as grpc from "@grpc/grpc-js";
import { connect, Contract, Identity, Signer, signers } from "@hyperledger/fabric-gateway";

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 8081);

const FABRIC_HOME =
  process.env.FABRIC_HOME ||
  path.join(process.env.HOME || "", "fabric-samples", "test-network");

const channelName = process.env.FABRIC_CHANNEL || "mychannel";
const chaincodeName = process.env.FABRIC_CHAINCODE || "evidence";

const cryptoPath = path.join(
  FABRIC_HOME,
  "organizations",
  "peerOrganizations",
  "org1.example.com"
);

const certPath = path.join(
  cryptoPath,
  "users",
  "Admin@org1.example.com",
  "msp",
  "signcerts"
);

const keyPath = path.join(
  cryptoPath,
  "users",
  "Admin@org1.example.com",
  "msp",
  "keystore"
);

const tlsCertPath = path.join(
  cryptoPath,
  "tlsca",
  "tlsca.org1.example.com-cert.pem"
);

const peerEndpoint = process.env.FABRIC_PEER_ENDPOINT || "localhost:7051";
const peerHostAlias =
  process.env.FABRIC_PEER_HOST_ALIAS || "peer0.org1.example.com";

function firstFile(directory: string): string {
  const files = fs.readdirSync(directory);

  if (files.length === 0) {
    throw new Error(`No files found in ${directory}`);
  }

  return path.join(directory, files[0]);
}

function newGrpcConnection(): grpc.Client {
  const tlsRootCert = fs.readFileSync(tlsCertPath);

  return new grpc.Client(
    peerEndpoint,
    grpc.credentials.createSsl(tlsRootCert),
    {
      "grpc.ssl_target_name_override": peerHostAlias,
    }
  );
}

function newIdentity(): Identity {
  const cert = fs.readFileSync(firstFile(certPath));

  return {
    mspId: "Org1MSP",
    credentials: cert,
  };
}

function newSigner(): Signer {
  const privateKeyPem = fs.readFileSync(firstFile(keyPath));
  const privateKey = crypto.createPrivateKey(privateKeyPem);

  return signers.newPrivateKeySigner(privateKey);
}

function getContract(): {
  contract: Contract;
  client: grpc.Client;
} {
  const client = newGrpcConnection();

  const gateway = connect({
    client,
    identity: newIdentity(),
    signer: newSigner(),
  });

  const network = gateway.getNetwork(channelName);
  const contract = network.getContract(chaincodeName);

  return { contract, client };
}

app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "netsecureai-fabric-gateway",
    channel: channelName,
    chaincode: chaincodeName,
  });
});

app.post("/anchor", async (req: Request, res: Response) => {
  let client: grpc.Client | undefined;

  try {
    const {
      record_id,
      record_type,
      analysis_id,
      device_id = "",
      vendor = "",
      framework = "",
      hash,
      hash_algorithm = "SHA-256",
      actor = "system",
      previous_hash = "",
    } = req.body;

    if (!record_id || !record_type || !analysis_id || !hash) {
      return res.status(400).json({
        error: "record_id, record_type, analysis_id and hash are required",
      });
    }

    const result = getContract();
    client = result.client;

    const transaction = result.contract.submitAsync(
      "CreateAuditRecord",
      {
        arguments: [
          record_id,
          record_type,
          analysis_id,
          device_id,
          vendor,
          framework,
          hash,
          hash_algorithm,
          actor,
          previous_hash,
        ],
        endorsingOrganizations: ["Org1MSP", "Org2MSP"],
      }
    );

    const transactionId = (await transaction).getTransactionId();

    return res.json({
      status: "anchored",
      transaction_id: transactionId,
      record_id,
      analysis_id,
      hash,
      hash_algorithm,
    });
  } catch (error) {
    console.error("Anchor error:", error);

    return res.status(500).json({
      status: "error",
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    client?.close();
  }
});

app.post("/verify", async (req: Request, res: Response) => {
  let client: grpc.Client | undefined;

  try {
    const { record_id, hash } = req.body;

    if (!record_id || !hash) {
      return res.status(400).json({
        error: "record_id and hash are required",
      });
    }

    const result = getContract();
    client = result.client;

    const resultBytes = await result.contract.evaluateTransaction(
      "VerifyHash",
      record_id,
      hash
    );

    const verified = Buffer.from(resultBytes).toString("utf8") === "true";

    const recordBytes = await result.contract.evaluateTransaction(
      "ReadAuditRecord",
      record_id
    );

    const recordDecoded = Buffer.from(recordBytes).toString("utf8");
    const record = JSON.parse(recordDecoded);

    return res.json({
      status: verified ? "verified" : "tampered",
      record_id,
      hash,
      blockchain_hash: record.hash,
      verified,
    });
  } catch (error) {
    console.error("Verify error:", error);

    return res.status(500).json({
      status: "error",
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    client?.close();
  }
});

app.get("/record/:recordId", async (req: Request, res: Response) => {
  let client: grpc.Client | undefined;

  try {
    const result = getContract();
    client = result.client;

    const resultBytes = await result.contract.evaluateTransaction(
      "ReadAuditRecord",
      String(req.params.recordId)
    );

    const decoded = Buffer.from(resultBytes).toString("utf8");
    return res.json(JSON.parse(decoded));
  } catch (error) {
    return res.status(404).json({
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    client?.close();
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`NetSecureAI Fabric Gateway running on port ${PORT}`);
  console.log(`Fabric home: ${FABRIC_HOME}`);
  console.log(`Channel: ${channelName}`);
  console.log(`Chaincode: ${chaincodeName}`);
});
