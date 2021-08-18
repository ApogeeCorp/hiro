/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package hiro

import (
	"context"

	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/golang/protobuf/ptypes/empty"
)

// ToProto converts the Secret to its protobuf conterpart
func (s Secret) ToProto() *pb.Secret {
	var algo pb.Secret_TokenAlgorithm

	if s.Algorithm != nil {
		algo = apiAlgoMap[*s.Algorithm]
	}

	return &pb.Secret{
		Id:         s.ID.String(),
		Type:       apiSecretMap[s.Type],
		InstanceId: s.InstanceID.String(),
		Algorithm:  &algo,
		Key:        s.RawKey,
	}
}

// FromProto convert the proto Secret to an api Secret
func (s *Secret) FromProto(p *pb.Secret) {
	var algo oauth.TokenAlgorithm

	if p.Algorithm != nil {
		algo = pbAlgoMap[*p.Algorithm]
	}

	s.ID = ID(p.Id)
	s.Type = pbSecretMap[p.Type]
	s.Algorithm = &algo
	s.InstanceID = ID(p.InstanceId)
	s.RawKey = p.Key
}

// SecretCreate implements the pb.HiroServer interface
func (s *RPCServer) SecretCreate(ctx context.Context, params *pb.SecretCreateRequest) (*pb.Secret, error) {
	algo := pbAlgoMap[params.Algorithm]

	sec, err := s.Controller.SecretCreate(ctx, SecretCreateInput{
		Type:       pbSecretMap[params.Type],
		InstanceID: ID(params.InstanceId),
		Algorithm:  &algo,
		Key:        params.Key,
	})
	if err != nil {
		return nil, err
	}

	return sec.ToProto(), nil
}

// SecreteDelete implements the pb.HiroServer interface
func (s *RPCServer) SecreteDelete(ctx context.Context, params *pb.SecretDeleteRequest) (*empty.Empty, error) {
	err := s.Controller.SecretDelete(ctx, SecretDeleteInput{
		SecretID: ID(params.Id),
	})

	return nil, err
}
