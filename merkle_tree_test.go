// Copyright 2017 Cameron Bergoon
// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"hash"
	"testing"
)

//TestSHA256Content implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestSHA256Content struct {
	x string
}

//CalculateHash hashes the values of a TestSHA256Content
func (t TestSHA256Content) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestSHA256Content) Equals(other Content) (bool, error) {
	return t.x == other.(TestSHA256Content).x, nil
}

//TestContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestMD5Content struct {
	x string
}

//CalculateHash hashes the values of a TestContent
func (t TestMD5Content) CalculateHash() ([]byte, error) {
	h := md5.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestMD5Content) Equals(other Content) (bool, error) {
	return t.x == other.(TestMD5Content).x, nil
}

func calHash(hash []byte, hashStrategy func() hash.Hash) ([]byte, error) {
	h := hashStrategy()
	if _, err := h.Write(hash); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

var table = []struct {
	testCaseId          int
	hashStrategy        func() hash.Hash
	hashStrategyName    string
	defaultHashStrategy bool
	contents            []Content
	expectedHash        []byte
	notInContents       Content
}{
	{
		testCaseId:          0,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "Hello",
			},
			TestSHA256Content{
				x: "Hi",
			},
			TestSHA256Content{
				x: "Hey",
			},
			TestSHA256Content{
				x: "Hola",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{206, 254, 70, 223, 66, 98, 26, 14, 101, 142, 83, 192, 203, 178, 28, 118, 133, 16, 138, 121, 14, 185, 226, 165, 131, 111, 105, 34, 54, 246, 220, 4},
	},
	{
		testCaseId:          1,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "Hello",
			},
			TestSHA256Content{
				x: "Hi",
			},
			TestSHA256Content{
				x: "Hey",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{63, 240, 237, 114, 142, 213, 228, 172, 93, 192, 198, 196, 190, 235, 23, 60, 147, 135, 7, 153, 180, 94, 144, 142, 154, 166, 53, 61, 42, 187, 63, 54},
	},
	{
		testCaseId:          2,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "Hello",
			},
			TestSHA256Content{
				x: "Hi",
			},
			TestSHA256Content{
				x: "Hey",
			},
			TestSHA256Content{
				x: "Greetings",
			},
			TestSHA256Content{
				x: "Hola",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{178, 121, 255, 26, 114, 25, 42, 112, 92, 202, 217, 133, 97, 230, 102, 163, 102, 225, 186, 82, 251, 231, 47, 194, 212, 253, 26, 40, 42, 95, 168, 108},
	},
	{
		testCaseId:          3,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "123",
			},
			TestSHA256Content{
				x: "234",
			},
			TestSHA256Content{
				x: "345",
			},
			TestSHA256Content{
				x: "456",
			},
			TestSHA256Content{
				x: "1123",
			},
			TestSHA256Content{
				x: "2234",
			},
			TestSHA256Content{
				x: "3345",
			},
			TestSHA256Content{
				x: "4456",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{101, 196, 9, 196, 60, 49, 184, 235, 89, 5, 214, 74, 3, 93, 110, 61, 163, 61, 60, 4, 245, 63, 228, 27, 18, 110, 165, 188, 229, 196, 125, 123},
	},
	{
		testCaseId:          4,
		hashStrategy:        sha256.New,
		hashStrategyName:    "sha256",
		defaultHashStrategy: true,
		contents: []Content{
			TestSHA256Content{
				x: "123",
			},
			TestSHA256Content{
				x: "234",
			},
			TestSHA256Content{
				x: "345",
			},
			TestSHA256Content{
				x: "456",
			},
			TestSHA256Content{
				x: "1123",
			},
			TestSHA256Content{
				x: "2234",
			},
			TestSHA256Content{
				x: "3345",
			},
			TestSHA256Content{
				x: "4456",
			},
			TestSHA256Content{
				x: "5567",
			},
		},
		notInContents: TestSHA256Content{x: "NotInTestTable"},
		expectedHash:  []byte{136, 27, 7, 151, 215, 19, 217, 58, 89, 221, 221, 123, 2, 35, 10, 34, 197, 59, 63, 133, 79, 62, 23, 14, 28, 210, 84, 170, 87, 9, 154, 192},
	},
	{
		testCaseId:          5,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "Hello",
			},
			TestMD5Content{
				x: "Hi",
			},
			TestMD5Content{
				x: "Hey",
			},
			TestMD5Content{
				x: "Hola",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{63, 103, 175, 82, 194, 240, 155, 114, 128, 249, 234, 57, 117, 94, 252, 93},
	},
	{
		testCaseId:          6,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "Hello",
			},
			TestMD5Content{
				x: "Hi",
			},
			TestMD5Content{
				x: "Hey",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{157, 243, 189, 250, 36, 102, 147, 4, 253, 41, 198, 195, 90, 117, 239, 32},
	},
	{
		testCaseId:          7,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "Hello",
			},
			TestMD5Content{
				x: "Hi",
			},
			TestMD5Content{
				x: "Hey",
			},
			TestMD5Content{
				x: "Greetings",
			},
			TestMD5Content{
				x: "Hola",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{115, 156, 191, 184, 167, 81, 150, 103, 14, 237, 158, 113, 114, 202, 204, 239},
	},
	{
		testCaseId:          8,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "123",
			},
			TestMD5Content{
				x: "234",
			},
			TestMD5Content{
				x: "345",
			},
			TestMD5Content{
				x: "456",
			},
			TestMD5Content{
				x: "1123",
			},
			TestMD5Content{
				x: "2234",
			},
			TestMD5Content{
				x: "3345",
			},
			TestMD5Content{
				x: "4456",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{193, 37, 164, 137, 29, 104, 166, 52, 32, 20, 214, 31, 193, 86, 247, 194},
	},
	{
		testCaseId:          9,
		hashStrategy:        md5.New,
		hashStrategyName:    "md5",
		defaultHashStrategy: false,
		contents: []Content{
			TestMD5Content{
				x: "123",
			},
			TestMD5Content{
				x: "234",
			},
			TestMD5Content{
				x: "345",
			},
			TestMD5Content{
				x: "456",
			},
			TestMD5Content{
				x: "1123",
			},
			TestMD5Content{
				x: "2234",
			},
			TestMD5Content{
				x: "3345",
			},
			TestMD5Content{
				x: "4456",
			},
			TestMD5Content{
				x: "5567",
			},
		},
		notInContents: TestMD5Content{x: "NotInTestTable"},
		expectedHash:  []byte{252, 223, 58, 193, 109, 54, 118, 145, 42, 5, 73, 192, 71, 201, 102, 133},
	},
}

func TestNewTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		if !table[i].defaultHashStrategy {
			continue
		}
		tree, err := NewTree(table[i].contents)
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestNewTreeWithHashingStrategy(t *testing.T) {
	for i := 0; i < len(table); i++ {
		tree, err := NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_MerkleRoot(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_RebuildTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		err = tree.RebuildTree()
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error:  %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_RebuildTreeWith(t *testing.T) {
	for i := 0; i < len(table)-1; i++ {
		if table[i].hashStrategyName != table[i+1].hashStrategyName {
			continue
		}
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		err = tree.RebuildTreeWith(table[i+1].contents)
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if bytes.Compare(tree.MerkleRoot(), table[i+1].expectedHash) != 0 {
			t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, table[i+1].expectedHash, tree.MerkleRoot())
		}
	}
}

func TestMerkleTree_VerifyTree(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		v1, err := tree.VerifyTree()
		if err != nil {
			t.Fatal(err)
		}
		if v1 != true {
			t.Errorf("[case:%d] error: expected tree to be valid", table[i].testCaseId)
		}
		tree.Root.Hash = []byte{1}
		tree.merkleRoot = []byte{1}
		v2, err := tree.VerifyTree()
		if err != nil {
			t.Fatal(err)
		}
		if v2 != false {
			t.Errorf("[case:%d] error: expected tree to be invalid", table[i].testCaseId)
		}
	}
}

func TestMerkleTree_VerifyContent(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if len(table[i].contents) > 0 {
			v, err := tree.VerifyContent(table[i].contents[0])
			if err != nil {
				t.Fatal(err)
			}
			if !v {
				t.Errorf("[case:%d] error: expected valid content", table[i].testCaseId)
			}
		}
		if len(table[i].contents) > 1 {
			v, err := tree.VerifyContent(table[i].contents[1])
			if err != nil {
				t.Fatal(err)
			}
			if !v {
				t.Errorf("[case:%d] error: expected valid content", table[i].testCaseId)
			}
		}
		if len(table[i].contents) > 2 {
			v, err := tree.VerifyContent(table[i].contents[2])
			if err != nil {
				t.Fatal(err)
			}
			if !v {
				t.Errorf("[case:%d] error: expected valid content", table[i].testCaseId)
			}
		}
		if len(table[i].contents) > 0 {
			tree.Root.Hash = []byte{1}
			tree.merkleRoot = []byte{1}
			v, err := tree.VerifyContent(table[i].contents[0])
			if err != nil {
				t.Fatal(err)
			}
			if v {
				t.Errorf("[case:%d] error: expected invalid content", table[i].testCaseId)
			}
			if err := tree.RebuildTree(); err != nil {
				t.Fatal(err)
			}
		}
		v, err := tree.VerifyContent(table[i].notInContents)
		if err != nil {
			t.Fatal(err)
		}
		if v {
			t.Errorf("[case:%d] error: expected invalid content", table[i].testCaseId)
		}
	}
}

func TestMerkleTree_String(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		if tree.String() == "" {
			t.Errorf("[case:%d] error: expected not empty string", table[i].testCaseId)
		}
	}
}

func TestMerkleTree_MerklePath(t *testing.T) {
	for i := 0; i < len(table); i++ {
		var tree *MerkleTree
		var err error
		if table[i].defaultHashStrategy {
			tree, err = NewTree(table[i].contents)
		} else {
			tree, err = NewTreeWithHashStrategy(table[i].contents, table[i].hashStrategy)
		}
		if err != nil {
			t.Errorf("[case:%d] error: unexpected error: %v", table[i].testCaseId, err)
		}
		for j := 0; j < len(table[i].contents); j++ {
			merklePath, index, _ := tree.GetMerklePath(table[i].contents[j])

			hash, err := tree.Leafs[j].calculateNodeHash()
			if err != nil {
				t.Errorf("[case:%d] error: calculateNodeHash error: %v", table[i].testCaseId, err)
			}
			h := sha256.New()
			for k := 0; k < len(merklePath); k+=2 {
				if (index[k] == 1 && index[k+1] == 2) { //is left
					hash = append(append(hash, merklePath[k]...), merklePath[k+1]...)
				}else{
					if (index[k] == 0 && index[k+1] == 2) { //is middle
					hash = append(append(merklePath[k], hash...), merklePath[k+1]...)
					}else{ //is right
						hash = append(append(merklePath[k], merklePath[k+1]...), hash...)
					}
				}
				if _, err := h.Write(hash); err != nil {
					t.Errorf("[case:%d] error: Write error: %v", table[i].testCaseId, err)
				}
				hash, err = calHash(hash, table[i].hashStrategy)
				if err != nil {
					t.Errorf("[case:%d] error: calHash error: %v", table[i].testCaseId, err)
				}
			}
			if bytes.Compare(tree.MerkleRoot(), hash) != 0 {
				t.Errorf("[case:%d] error: expected hash equal to %v got %v", table[i].testCaseId, hash, tree.MerkleRoot())
			}
		}
	}
}
