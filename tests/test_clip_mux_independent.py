"""Generated physical clip controls; no provider/capability or edit approval."""
import copy
import hashlib
import json
import subprocess
from fractions import Fraction
from pathlib import Path

import pytest

from talkcut.project import TalkCutError, artifact_ref, atomic_json, read_json
from talkcut.review import _clip, build_review_bundle, validate_review_request


def run(argv):
    return subprocess.run(argv, capture_output=True, check=True, timeout=60).stdout


def generate(path, duration=180, audio_duration=None):
    run(['ffmpeg', '-nostdin', '-v', 'error', '-n', '-f', 'lavfi', '-i',
         f'testsrc2=size=96x64:rate=2:duration={duration}', '-f', 'lavfi', '-i',
         f'sine=frequency=440:sample_rate=8000:duration={audio_duration or duration}',
         '-c:v', 'libx264', '-c:a', 'aac', str(path)])
    return artifact_ref(path)


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    return generate(tmp_path_factory.mktemp('generated-av') / 'source.mp4')


def packets(path):
    values = json.loads(run(['ffprobe', '-v', 'error', '-show_packets', '-show_data_hash',
                             'sha256', '-of', 'json', str(path)]))['packets']
    return {index: [{k: v for k, v in row.items() if k != 'pos'} for row in values
                    if row['stream_index'] == index] for index in (0, 1)}


def decoded_sha(path, kind):
    options = ['-map', '0:v', '-pix_fmt', 'yuv420p', '-f', 'rawvideo'] if kind == 'video' else ['-map', '0:a', '-c:a', 'pcm_f32le', '-f', 'f32le']
    process = subprocess.Popen(['ffmpeg', '-nostdin', '-v', 'error', '-xerror', '-i',
                                str(path), *options, '-'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    with process.stdout:
        digest = hashlib.file_digest(process.stdout, 'sha256').hexdigest()
    assert process.wait(timeout=60) == 0
    assert process.stderr is not None
    with process.stderr:
        assert not process.stderr.read()
    return digest


def compare_original_mux(clip, path):
    receipt = read_json(clip['extraction_receipt']['path'])
    command = receipt['command'][:]
    index = command.index('-max_interleave_delta')
    assert command[index + 1] == '0'
    del command[index:index + 2]
    command[-1] = str(path)
    run(command)
    current = clip['clip']['path']
    assert packets(current) == packets(path)
    assert all(decoded_sha(current, kind) == decoded_sha(path, kind) for kind in ('video', 'audio'))


def request_proof(clip, deps, root):
    request = {'schema_version': 'review-request/v1', 'scope': 'analysis',
               'dependencies': deps, 'inputs': [clip], 'input_clip_hashes': [clip['clip']['sha256']],
               'intervals': [clip['interval']]}
    path = root / 'request.json'
    atomic_json(path, request)
    return request, {'request': artifact_ref(path), 'dependencies': deps}


def test_alternate_audio_offset_preserves_full_packets_clocks_and_exact_gate(generated, tmp_path):
    audio = tmp_path / 'other-tone.wav'
    run(['ffmpeg', '-nostdin', '-v', 'error', '-n', '-f', 'lavfi', '-i',
         'sine=frequency=920:sample_rate=48000:duration=180', str(audio)])
    alternate = {**artifact_ref(audio), 'offset': '5', 'origin': '0', 'mapping_verified': True}
    deps = {'source_hashes': {'screen': generated['sha256'], 'speaker': alternate['sha256']}}
    before = [artifact_ref(generated['path']), artifact_ref(audio)]
    clip = _clip(generated, (Fraction(15), Fraction(45)), tmp_path / 'clip', deps, audio_source=alternate)
    receipt = read_json(clip['extraction_receipt']['path'])
    assert receipt['video_native_interval'] == ['15', '45']
    assert receipt['audio_native_interval'] == ['10', '40']
    compare_original_mux(clip, tmp_path / 'old-mux.mp4')
    request, execution = request_proof(clip, deps, tmp_path)
    validate_review_request(request, execution)
    assert before == [artifact_ref(generated['path']), artifact_ref(audio)]


def test_long_deletion_materialization_keeps_full_130_seconds(generated, tmp_path):
    output = tmp_path / 'actual-concat.mp4'
    graph = '[0:v]trim=0:30,setpts=PTS-STARTPTS[v0];[0:a]atrim=0:30,asetpts=PTS-STARTPTS[a0];[0:v]trim=150:180,setpts=PTS-STARTPTS[v1];[0:a]atrim=150:180,asetpts=PTS-STARTPTS[a1];[v0][a0][v1][a1]concat=n=2:v=1:a=1[v][a]'
    run(['ffmpeg', '-nostdin', '-v', 'error', '-n', '-i', generated['path'], '-filter_complex',
         graph, '-map', '[v]', '-map', '[a]', '-c:v', 'libx264', '-c:a', 'aac', str(output)])
    output_ref = artifact_ref(output)
    deps = {'source_hashes': {'screen': generated['sha256']}, 'output_hash': output_ref['sha256']}
    timeline = {'domain': {'start': '0', 'end': '180'}, 'duration': '60', 'retained': [
        {'source_start': '0', 'source_end': '30', 'output_start': '0', 'output_end': '30'},
        {'source_start': '150', 'source_end': '180', 'output_start': '30', 'output_end': '60'}]}
    bundle = build_review_bundle(tmp_path, timeline, generated, output_ref, tmp_path / 'review', deps, include_source_analysis=False)
    requests = [read_json(ref['path']) for ref in bundle['requests']]
    deletion = next(row for row in requests if row['scope'] == 'deletion')
    assert deletion['intervals'] == [['25', '155']]
    assert bundle['actual_deletions'] == [['30', '150']]
    assert not bundle['verified_review_coverage']
    assert all(row['status'] == 'UNVERIFIED' for row in requests)
    compare_original_mux(deletion['inputs'][0], tmp_path / 'old-long-mux.mp4')
    assert artifact_ref(generated['path']) == generated
    assert artifact_ref(output) == output_ref


@pytest.mark.parametrize('damage', ['early_audio_eof', 'requested_past_eof', 'timeout'])
def test_failure_never_promotes_partial_or_loses_original(generated, tmp_path, damage):
    source = generate(tmp_path / 'early-eof.mp4', 60, 10) if damage == 'early_audio_eof' else generated
    interval = (Fraction(170), Fraction(200)) if damage == 'requested_past_eof' else (Fraction(0), Fraction(30))
    directory = tmp_path / 'failed'
    error_type = subprocess.TimeoutExpired if damage == 'timeout' else TalkCutError
    with pytest.raises(error_type):
        _clip(source, interval, directory, {}, timeout=0.0001 if damage == 'timeout' else 60)
    assert not (directory / 'clip.mp4').exists()
    assert not (directory / 'receipt.json').exists()
    failure = read_json(directory / 'failure.json')
    assert failure['status'] == 'UNVERIFIED' and failure['owner_acceptance'] == 'pending'
    assert (directory / 'ffmpeg.log').exists()
    if damage != 'timeout':
        assert (directory / 'clip.partial.mp4').exists()
    before_retry = artifact_ref(directory / 'failure.json')
    _clip(generated, (Fraction(0), Fraction(30)), tmp_path / 'successful-retry', {})
    assert artifact_ref(directory / 'failure.json') == before_retry
    assert artifact_ref(source['path']) == source


@pytest.mark.parametrize('damage', ['stale_parent_hash', 'rebound_mp4_tail'])
def test_stale_or_rebound_tampering_still_refuses(generated, tmp_path, damage):
    if damage == 'stale_parent_hash':
        stale = {**generated, 'sha256': 'f' * 64}
        with pytest.raises(TalkCutError):
            _clip(stale, (Fraction(0), Fraction(30)), tmp_path / 'rejected', {})
        assert not (tmp_path / 'rejected').exists()
        return
    deps = {'source_hashes': {'screen': generated['sha256']}}
    clip = _clip(generated, (Fraction(0), Fraction(30)), tmp_path / 'clip', deps)
    before = copy.deepcopy(clip)
    path = Path(clip['clip']['path'])
    path.write_bytes(path.read_bytes() + b'generated-audit-tail')
    clip['clip'] = artifact_ref(path)
    receipt_path = Path(clip['extraction_receipt']['path'])
    receipt = read_json(receipt_path)
    receipt['output_sha256'] = clip['clip']['sha256']
    atomic_json(receipt_path, receipt)
    clip['extraction_receipt'] = artifact_ref(receipt_path)
    request, execution = request_proof(clip, deps, tmp_path)
    with pytest.raises(TalkCutError, match='do not reproduce'):
        validate_review_request(request, execution)
    assert clip['clip']['sha256'] != before['clip']['sha256']
    assert artifact_ref(generated['path']) == generated
