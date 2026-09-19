package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

type EvidenceRecord struct {
	RecordID      string `json:"record_id"`
	RecordType    string `json:"record_type"`
	AnalysisID    string `json:"analysis_id"`
	DeviceID      string `json:"device_id"`
	Vendor        string `json:"vendor"`
	Framework     string `json:"framework"`
	Hash          string `json:"hash"`
	HashAlgorithm string `json:"hash_algorithm"`
	Actor         string `json:"actor"`
	Timestamp     string `json:"timestamp"`
	PreviousHash  string `json:"previous_hash"`
}

type EvidenceContract struct {
	contractapi.Contract
}

func (c *EvidenceContract) CreateAuditRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	recordType string,
	analysisID string,
	deviceID string,
	vendor string,
	framework string,
	hashValue string,
	hashAlgorithm string,
	actor string,
	previousHash string,
) error {

	exists, err := c.RecordExists(ctx, recordID)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("record %s already exists", recordID)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}

	record := EvidenceRecord{
		RecordID:      recordID,
		RecordType:    recordType,
		AnalysisID:    analysisID,
		DeviceID:      deviceID,
		Vendor:        vendor,
		Framework:     framework,
		Hash:          hashValue,
		HashAlgorithm: hashAlgorithm,
		Actor:         actor,
		Timestamp:     txTimestamp.AsTime().UTC().Format("2006-01-02T15:04:05Z"),
		PreviousHash:  previousHash,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(recordID, data)
}

func (c *EvidenceContract) ReadAuditRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (*EvidenceRecord, error) {

	data, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, fmt.Errorf("record %s does not exist", recordID)
	}

	var record EvidenceRecord

	err = json.Unmarshal(data, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func (c *EvidenceContract) RecordExists(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) (bool, error) {

	data, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return false, err
	}

	return data != nil, nil
}

func (c *EvidenceContract) VerifyHash(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	suppliedHash string,
) (bool, error) {

	record, err := c.ReadAuditRecord(ctx, recordID)
	if err != nil {
		return false, err
	}

	return record.Hash == suppliedHash, nil
}

func (c *EvidenceContract) GetAuditHistory(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) ([]map[string]interface{}, error) {

	iterator, err := ctx.GetStub().GetHistoryForKey(recordID)
	if err != nil {
		return nil, err
	}

	defer iterator.Close()

	var history []map[string]interface{}

	for iterator.HasNext() {
		modification, err := iterator.Next()
		if err != nil {
			return nil, err
		}

		entry := map[string]interface{}{
			"tx_id":     modification.TxId,
			"is_delete": modification.IsDelete,
		}

		if modification.Timestamp != nil {
			entry["timestamp"] = modification.Timestamp.AsTime().UTC().Format("2006-01-02T15:04:05Z")
		}

		if len(modification.Value) > 0 {
			var record EvidenceRecord

			if err := json.Unmarshal(modification.Value, &record); err == nil {
				entry["record"] = record
			}
		}

		history = append(history, entry)
	}

	return history, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&EvidenceContract{})
	if err != nil {
		panic(err.Error())
	}

	if err := chaincode.Start(); err != nil {
		panic(err.Error())
	}
}
