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
	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/golang/protobuf/ptypes"
)

var (
	pbSecretMap = map[pb.Secret_SecretType]SecretType{
		pb.Secret_TOKEN:   SecretTypeToken,
		pb.Secret_SESSION: SecretTypeSession,
	}

	pbAlgoMap = map[pb.Secret_TokenAlgorithm]oauth.TokenAlgorithm{
		pb.Secret_RS256: oauth.TokenAlgorithmRS256,
		pb.Secret_HS256: oauth.TokenAlgorithmHS256,
	}

	apiSecretMap = map[SecretType]pb.Secret_SecretType{
		SecretTypeToken:   pb.Secret_TOKEN,
		SecretTypeSession: pb.Secret_SESSION,
	}

	apiAlgoMap = map[oauth.TokenAlgorithm]pb.Secret_TokenAlgorithm{
		oauth.TokenAlgorithmRS256: pb.Secret_RS256,
		oauth.TokenAlgorithmHS256: pb.Secret_HS256,
	}
)

// AudienceList handles the AudienceList rpc request
func (s *RPCServer) AudienceList(req *pb.AudienceListRequest, stream pb.Hiro_AudienceListServer) error {
	auds, err := s.ctrl.AudienceList(stream.Context(), AudienceListInput{
		Limit:  &req.Limit,
		Offset: &req.Offset,
	})
	if err != nil {
		return err
	}

	for _, a := range auds {
		secrets := make([]*pb.Secret, 0)

		for _, s := range a.Secrets {
			var algo pb.Secret_TokenAlgorithm

			if s.Algorithm != nil {
				algo = apiAlgoMap[*s.Algorithm]
			}

			secrets = append(secrets, &pb.Secret{
				Id:         s.ID.String(),
				Type:       apiSecretMap[s.Type],
				AudienceId: a.ID.String(),
				Algorithm:  algo,
				Key:        s.Key,
			})
		}

		createdAt, err := ptypes.TimestampProto(a.CreatedAt)
		if err != nil {
			return err
		}

		updatedAt, err := ptypes.TimestampProto(safe.Time(a.UpdatedAt))
		if err != nil {
			return err
		}

		pa := &pb.Audience{
			Id:          a.ID.String(),
			Name:        a.Name,
			Slug:        a.Slug,
			Description: safe.String(a.Description),
			Secrets:     secrets,
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
		}

		stream.Send(pa)
	}

	return nil
}
