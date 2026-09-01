from kitelon_engine.context import ScanContext
from kitelon_engine.pipelines import batch


def run(ctx: ScanContext) -> int:
    ctx.options.setdefault("threads", 20)
    return batch.batch_ports(ctx)
